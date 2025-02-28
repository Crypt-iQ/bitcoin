#!/usr/bin/env python3
# Copyright (c) 2022- The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test compact block logic during IBD
"""

import time

from test_framework.blocktools import (
        create_block,
        create_coinbase
)
from test_framework.messages import (
        MSG_BLOCK,
        MSG_TYPE_MASK,
        HeaderAndShortIDs,
)
from test_framework.p2p import (
        CBlockHeader,
        msg_block,
        msg_headers,
        P2PDataStore,
        msg_cmpctblock,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
        assert_equal,
)

class P2PNoReply(P2PDataStore):
    def on_getdata(self, message):
        pass

    def on_getheaders(self, message):
        pass

class P2PStaller(P2PDataStore):
    def __init__(self, stall_block):
        self.stall_block = stall_block
        super().__init__()

    def on_getdata(self, message):
        for inv in message.inv:
            self.getdata_requests.append(inv.hash)
            if (inv.type & MSG_TYPE_MASK) == MSG_BLOCK:
                if (inv.hash != self.stall_block):
                    self.send_message(msg_block(self.block_store[inv.hash]))

    def on_getheaders(self, message):
        pass

class P2PIBDCmpctTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def run_test(self):
        NUM_BLOCKS = 1025
        NUM_PEERS = 4
        node = self.nodes[0]
        tip = int(node.getbestblockhash(), 16)
        blocks = []
        height = 1
        block_time = node.getblock(node.getbestblockhash())['time'] + 1
        self.log.info("Prepare blocks without sending them to the node")
        block_dict = {}
        for _ in range(NUM_BLOCKS):
            blocks.append(create_block(tip, create_coinbase(height), block_time))
            blocks[-1].solve()
            tip = blocks[-1].sha256
            block_time += 1
            height += 1
            block_dict[blocks[-1].sha256] = blocks[-1]
        stall_block = blocks[0].sha256

        peers = []

        self.mocktime = int(time.time()) + 1
        node.setmocktime(self.mocktime)

        # Add a new peer that will not respond to requests for `stall_block`.
        peers.append(node.add_outbound_p2p_connection(P2PStaller(stall_block), p2p_idx=0, connection_type="outbound-full-relay"))
        peers[0].block_store = block_dict
        # Construct a HEADERS message that only includes `stall_block`.
        short_headers_message = msg_headers()
        short_headers_message.headers = [CBlockHeader(b) for b in blocks[:1]]
        peers[0].send_message(short_headers_message)
        peers[0].sync_with_ping()

        second_stall_block = blocks[1].sha256

        # Create a HEADERS message that contains all of the blocks. Having peers that send this emulate honest peers
        # that are trying to serve the node the full block download window.
        all_headers_message = msg_headers()
        all_headers_message.headers = [CBlockHeader(b) for b in blocks]

        # Add a new peer that will not respond to any block requests.
        peers.append(node.add_outbound_p2p_connection(P2PNoReply(), p2p_idx=1, connection_type="outbound-full-relay"))
        peers[1].block_store = block_dict
        # Note that the node will not request `stall_block` from this peer since it's already in flight with peer=0.
        peers[1].send_message(all_headers_message)
        peers[1].sync_with_ping()

        # Add a new peer that will respond to all requests. Note that the first several blocks won't be requested from this
        # peer. All of the other blocks will be fulfilled, however, they don't advance the chain tip since `stall_block`
        # was never received.
        peers.append(node.add_outbound_p2p_connection(P2PStaller(1337), p2p_idx=2, connection_type="outbound-full-relay"))
        peers[2].block_store = block_dict
        peers[2].send_message(all_headers_message)
        peers[2].sync_with_ping()

        # Create another peer that can serve the headers chain for good measure.
        peers.append(node.add_outbound_p2p_connection(P2PStaller(1337), p2p_idx=3, connection_type="outbound-full-relay"))
        peers[3].block_store = block_dict
        peers[3].send_message(all_headers_message)
        peers[3].sync_with_ping()

        self.log.info("Sending compact blocks should reset m_stalling_since.")

        time.sleep(5)

        # If we were to move mocktime forward here, peer=0 will get disconnected. Uncommenting the below lines shows
        # that peer=0 will get disconnected.
        '''
        self.all_sync_send_with_ping(peers)
        self.mocktime += 3
        node.setmocktime(self.mocktime)
        self.all_sync_send_with_ping(peers)
        peers[0].wait_for_disconnect()
        '''

        # peer=0 will send CMPCTBLOCK for `second_stall_block` with non-empty but bogus `shortids` to hit this branch:
        # https://github.com/bitcoin/bitcoin/blob/3c1f72a36700271c7c1293383549c3be29f28edb/src/net_processing.cpp#L4449-L4450
        # The call to RemoveBlockRequest will reset m_stalling_since for peer=0 even though the peer did not give us
        # an actual block and simply announced CMPCTBLOCK without the node sending us a SENDCMPCT requesting high-bandwidth
        # mode.
        cmpct_block = HeaderAndShortIDs()
        cmpct_block.initialize_from_block(blocks[1])
        cmpct_block.shortids.append(0x5)
        peers[0].send_message(msg_cmpctblock(cmpct_block.to_p2p()))
        peers[0].sync_with_ping()

        # Advancing the time should not disconnect any peer since m_stalling_since was reset above.
        self.all_sync_send_with_ping(peers)
        self.mocktime += 2
        node.setmocktime(self.mocktime)
        self.all_sync_send_with_ping(peers)

        # Reset m_stalling_since.
        peers[0].send_message(msg_cmpctblock(cmpct_block.to_p2p()))
        peers[0].sync_with_ping()

        # Advance the time.
        self.all_sync_send_with_ping(peers)
        self.mocktime += 2
        node.setmocktime(self.mocktime)
        self.all_sync_send_with_ping(peers)

        # Reset m_stalling_since again.
        peers[0].send_message(msg_cmpctblock(cmpct_block.to_p2p()))
        peers[0].sync_with_ping()

        self.all_sync_send_with_ping(peers)
        self.mocktime += 2
        node.setmocktime(self.mocktime)
        self.all_sync_send_with_ping(peers)

        time.sleep(5)

        # Assert false so we can examine the logs.
        assert(False)

    def total_bytes_recv_for_blocks(self):
        total = 0
        for info in self.nodes[0].getpeerinfo():
            if ("block" in info["bytesrecv_per_msg"].keys()):
                total += info["bytesrecv_per_msg"]["block"]
        return total

    def all_sync_send_with_ping(self, peers):
        for p in peers:
            if p.is_connected:
                p.sync_with_ping()

    def is_block_requested(self, peers, hash):
        for p in peers:
            if p.is_connected and (hash in p.getdata_requests):
                return True
        return False


if __name__ == '__main__':
    P2PIBDCmpctTest(__file__).main()
