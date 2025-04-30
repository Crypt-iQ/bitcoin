#!/usr/bin/env python3
# Copyright (c) 2025 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.blocktools import (
    create_block,
    create_coinbase,
    create_tx_with_script,
)
from test_framework.messages import (
    COIN,
    msg_block,
    msg_headers,
    msg_sendcmpct,
)
from test_framework.p2p import (
    P2PDataStore,
)
from test_framework.script import (
    OP_TRUE,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

class DummyNode(P2PDataStore):
    def __init__(self):
        super().__init__()
        self.getdata_received = {}
        self.requested_hb = False

    def on_getdata(self, message):
        for request in message.inv:
            self.getdata_received[request.hash] = True
        pass

    def on_inv(self, message):
        # Do not respond to INV. This is not strictly necessary, but helps reduce the noise in the
        # debug log.
        pass

    def on_sendcmpct(self, message):
        self.requested_hb = message.announce

    def wait_until_requested(self, blocks):
        # Wait until we've received a GETDATA for each passed-in block.
        def test_function():
            for block in blocks:
                if block not in self.getdata_received:
                    return False
            return True 
        self.wait_until(test_function, timeout=10)

# This test demonstrates that, if blocks are received OOO (which can happen during IBD and even
# occasionally out of IBD), the reward/punishment mechanism based on querying mapBlockSource in the
# BlockChecked callback can be circumvented. In other words, it is possible to serve bad blocks and
# not get punished, or serve good blocks and not get rewarded.
class MapBlockSourceTest(BitcoinTestFramework):
    def set_test_params(self):
        # Note that setup_clean_chain is not set to True because we would have to leave IBD to properly
        # call test_reward.
        self.num_nodes = 1

    # This sub-test shows that the punishment mechanism can be bypassed if an OOO invalid block is
    # received. Note that even though this does not test punishment-avoidance during IBD, it is still
    # possible.
    def test_punishment(self):
        # First, demonstrate that it is possible for a peer to serve an invalid block and not be punished.
        # The block must be received out-of-order.
        node = self.nodes[0]
        peer1 = node.add_p2p_connection(DummyNode())
        peer2 = node.add_p2p_connection(DummyNode())

        self.log.info("Creating a new valid block")
        
        best_block = node.getblock(node.getbestblockhash())
        tip = int(node.getbestblockhash(), 16)
        height = best_block["height"] + 1
        block_time = best_block["time"] + 1
        block1 = create_block(tip, create_coinbase(height), block_time)
        block1.solve()

        self.log.info("Creating an invalid block that builds off of the previous valid block")

        tip = block1.sha256
        height += 1
        block_time += 1

        # The block will be invalid because the below transaction spends an immature coinbase output.
        tx = create_tx_with_script(block1.vtx[0], 0, script_sig=bytes([OP_TRUE]), amount=50 * COIN)
        block2 = create_block(tip, create_coinbase(height), block_time, txlist=[tx])
        block2.solve()

        self.log.info("First peer announcing both blocks to test node.")

        # Let the first peer announce the headers for both blocks.
        peer1.send_and_ping(msg_headers([block1]))
        peer1.send_and_ping(msg_headers([block2]))

        # Wait until the test node requests both blocks from the first peer.
        peer1.wait_until_requested([block1.sha256, block2.sha256])

        self.log.info("First peer sending over invalid block, no punishment should happen")

        # Because the test node does not yet have the parent block, they won't be able to tell that
        # the block is invalid yet.
        peer1.send_and_ping(msg_block(block2))
        assert_equal(peer1.is_connected, True)

        self.log.info("Second peer sending over the exact same invalid block, clearing mapBlockSource")

        # The second peer sends over the same invalid block. This will cause mapBlockSource to be erased
        # from because ProcessNewBlock will have new_block set to false. This will call mapBlockSource.erase.
        # The second peer will remain connected.
        peer2.send_and_ping(msg_block(block2))
        assert_equal(peer2.is_connected, True)

        self.log.info("First peer sending over valid parent block, no punishment should happen")

        # Send over the the valid block. This will cause the test to attempt to connect the second invalid
        # block and invoke the BlockChecked callback. Since the mapBlockSource entry was previously removed
        # by the second peer sending the invalid block, the first peer that served the invalid block will
        # not be punished.
        peer1.send_and_ping(msg_block(block1))

        # Assert that the first peer is not disconnected when the test node validates block1 and invalidates
        # block2.
        assert_equal(peer1.is_connected, True)

        # Also assert that the second peer is not punished for sending the invalid block.
        peer2.sync_with_ping()
        assert_equal(peer2.is_connected, True)

        # The test node should have advanced the tip to block1.
        tip = node.getbestblockhash()
        assert_equal(tip, block1.hash)

    # This sub-test shows that the mapBlockSource-based reward mechanism can be bypassed if an OOO valid
    # block is received. This means a malicious peer, in theory, could prevent some of our peers from becoming
    # high-bandwidth compact-block relaying peers. Because reward only happens outside of IBD, this does not
    # seem very concerning as blocks are typically not received OOO when we're caught up. This does demonstrate
    # the mapBlockSource is buggy, however.
    def test_reward(self):
        node = self.nodes[0]
        peer1 = node.add_p2p_connection(DummyNode())
        peer2 = node.add_p2p_connection(DummyNode())
        peer3 = node.add_p2p_connection(DummyNode())

        # Have all three peers send over a SENDCMPCT so that they are eligible for reward via the
        # BlockChecked callback.
        peer1.send_and_ping(msg_sendcmpct(announce=False, version=2))
        peer2.send_and_ping(msg_sendcmpct(announce=False, version=2))
        peer3.send_and_ping(msg_sendcmpct(announce=False, version=2))

        self.log.info("Creating a new valid block")

        best_block = node.getblock(node.getbestblockhash())
        tip = int(node.getbestblockhash(), 16)
        height = best_block["height"] + 1
        block_time = best_block["time"] + 1
        block1 = create_block(tip, create_coinbase(height), block_time)
        block1.solve()

        self.log.info("Creating a valid block that builds off of the previous valid block")

        tip = block1.sha256
        height += 1
        block_time += 1
        block2 = create_block(tip, create_coinbase(height), block_time)
        block2.solve()

        self.log.info("Announcing both blocks to test node.")

        # We don't let peer1 announce the first block to the test node since we are asserting that peer1
        # does not receive sendcmpct with announce set to True. If peer1 sends the first block, it will
        # get promoted and we are trying to test that peer1 does not get promoted when serving the second
        # block. We don't want peer2 to serve the first block either since we also assert that peer2 does
        # not get promoted.
        peer3.send_and_ping(msg_headers([block1]))
        peer1.send_and_ping(msg_headers([block2]))

        # Wait until the test node requests both blocks.
        peer3.wait_until_requested([block1.sha256])
        peer1.wait_until_requested([block2.sha256])

        self.log.info("First peer sending over the second valid block, no reward should happen")

        peer1.send_and_ping(msg_block(block2))
        assert_equal(peer1.requested_hb, False)

        self.log.info("Second peer sending over the same second block, clearing mapBlockSource")

        peer2.send_and_ping(msg_block(block2))
        assert_equal(peer2.requested_hb, False)

        self.log.info("Sending the first block via an unrelated peer")

        peer3.send_and_ping(msg_block(block1))
        assert_equal(peer3.requested_hb, True)

        self.log.info("Assert that neither peer that announced the second block is rewarded")

        peer1.sync_with_ping()
        assert_equal(peer1.requested_hb, False)
        assert_equal(peer1.is_connected, True)

        peer2.sync_with_ping()
        assert_equal(peer2.requested_hb, False)
        assert_equal(peer2.is_connected, True)

        # Assert that the test node's tip has been advanced to block2.
        tip = node.getbestblockhash()
        assert_equal(tip, block2.hash)

    # This sub-test shows that in the case of a stale chain tip, the peer that provided the tip will not
    # be punished or rewarded.
    def test_staletip(self):
        node = self.nodes[0]
        peer1 = node.add_p2p_connection(DummyNode())
        peer2 = node.add_p2p_connection(DummyNode())
        peer3 = node.add_p2p_connection(DummyNode())

        # Have all three peers send over SENDCMPCT so they are eligible for reward.
        peer1.send_and_ping(msg_sendcmpct(announce=False, version=2))
        peer2.send_and_ping(msg_sendcmpct(announce=False, version=2))
        peer3.send_and_ping(msg_sendcmpct(announce=False, version=2))

        # Generate a new block, this will be the parent of the stale tip and the future tip.
        self.log.info("Creating new valid block")

        best_block = node.getblock(node.getbestblockhash())
        tip = int(node.getbestblockhash(), 16)
        height = best_block["height"] + 1
        block_time = best_block["time"] + 1
        block1 = create_block(tip, create_coinbase(height), block_time)
        block1.solve()

        self.log.info("Creating future tip that builds off valid block")

        tip = block1.sha256
        height += 1
        block_time += 1
        block2 = create_block(tip, create_coinbase(height), block_time)
        block2.solve()

        # Create the stale tip.
        self.log.info("Creating stale tip that builds off valid block")

        # We do not need to modify the height here.
        tip = block1.sha256
        block_time += 100
        stale_block = create_block(tip, create_coinbase(height), block_time)
        stale_block.solve()

        self.log.info("Giving the valid parent block to the test node")

        peer1.send_and_ping(msg_headers([block1]))
        peer1.wait_until_requested([block1.sha256])
        peer1.send_and_ping(msg_block(block1))
        assert_equal(peer1.requested_hb, True)

        self.log.info("Giving the future tip to the test node")

        peer2.send_and_ping(msg_headers([block2]))
        peer2.wait_until_requested([block2.sha256])
        peer2.send_and_ping(msg_block(block2))
        assert_equal(peer2.requested_hb, True)

        self.log.info("Giving the stale tip to the test node")

        # If this is indeed a stale tip, the BlockChecked callback will never be called. This means that
        # a high-bandwidth SENDCMPCT message won't be received from the test node.
        peer3.send_and_ping(msg_headers([stale_block]))
        peer3.wait_until_requested([stale_block.sha256])
        peer3.send_and_ping(msg_block(stale_block))
        assert_equal(peer3.requested_hb, False)

    def run_test(self):
        self.log.info("Testing punishment-bypass")
        self.test_punishment()

        self.log.info("Testing reward-bypass")
        self.test_reward()

        self.log.info("Testing stale tip")
        self.test_staletip()

if __name__ == '__main__':
    MapBlockSourceTest(__file__).main()
