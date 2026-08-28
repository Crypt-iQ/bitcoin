#!/usr/bin/env python3
# Copyright (c) 2014-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the invalidateblock RPC."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.address import ADDRESS_BCRT1_UNSPENDABLE_DESCRIPTOR
from test_framework.blocktools import (
    create_block,
)
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)

import random
import threading
import time

class InvalidateTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3

    def setup_network(self):
        self.setup_nodes()

    def add_options(self, parser):
        parser.add_argument(
            "--race-attempts", dest="race_attempts", type=int, default=0,
            help="Attempts for the timing-dependent m_best_header race test (0 to skip)")

    def test_best_header_race(self, attempts):
        """Race a fork header against InvalidateBlock's disconnect loop.

        InvalidateBlock snapshots highpow_outofchain_headers under cs_main and then
        releases cs_main for every DisconnectTip iteration. Inside the loop m_best_header
        is reset to new_tip and only re-raised from that stale snapshot, and the final
        RecalculateBestHeader is gated on m_best_header descending from to_mark_failed.
        A header that arrives in one of the gaps is in neither, so m_best_header can be
        left below a non-failed block.

        The racing header is built at the same height as the active tip, so its chain work
        equals m_best_header's at arrival time and AddToBlockIndex (strict <) leaves
        m_best_header alone. On regtest -checkblockindex is on, so a win aborts the node at
        the assert in ChainstateManager::CheckBlockIndex. Run with -checkblockindex=0 to see
        the softer getblockchaininfo/getchaintips detector below instead of a crash.
        """
        self.log.info(f"Race a fork header against invalidateblock ({attempts} attempts)")
        node = self.nodes[2]
        # Isolate the node: a peer feeding it headers would perturb m_best_header.
        self.disconnect_nodes(1, 2)

        # Separate RPC connection, so the header can be submitted while
        # invalidateblock is still in flight on the main one.
        racer = node.create_new_rpc_connection()
        racer.getblockcount()  # prime the connection so setup latency is out of the way

        genesis_hash = int(node.getblockhash(0), 16)
        genesis_time = node.getblock(node.getblockhash(0))["time"]
        self.generatetodescriptor(node, 20, ADDRESS_BCRT1_UNSPENDABLE_DESCRIPTOR, sync_fun=self.no_op)

        # A fork off genesis that trails the active chain by one block. Building it up
        # front means each attempt only has to submit a single header. It is in the
        # snapshot, so it also pins the floor m_best_header can settle on.
        fork_tip = None
        for height in range(1, node.getblockcount()):
            prev = genesis_hash if fork_tip is None else fork_tip.hash_int
            fork_tip = create_block(prev, height=height, ntime=genesis_time + height)
            fork_tip.solve()
            node.submitheader(fork_tip.serialize().hex())
        fork_height = node.getblockcount() - 1

        for attempt in range(attempts):
            tip_hash = node.getbestblockhash()
            tip_height = node.getblockcount()
            assert_equal(fork_height, tip_height - 1)
            assert_equal(node.getblockchaininfo()["headers"], tip_height)

            racing = create_block(fork_tip.hash_int, height=tip_height,
                                  ntime=genesis_time + tip_height)
            racing.solve()
            racing_hex = racing.serialize().hex()

            # Aim to land in the gap between the snapshot and the first DisconnectTip.
            # The delay is randomised because that gap is microseconds wide and the only
            # lever we have is jitter across many attempts.
            start = threading.Event()
            delay = random.uniform(0, 0.002)

            def submit():
                start.wait()
                time.sleep(delay)
                racer.submitheader(racing_hex)

            thread = threading.Thread(target=submit)
            thread.start()
            start.set()
            try:
                node.invalidateblock(tip_hash)
            except Exception as e:
                thread.join()
                raise AssertionError(
                    f"attempt {attempt}: node stopped responding during invalidateblock, "
                    f"check debug.log for the CheckBlockIndex assertion ({e})")
            thread.join()

            # Softer detector, for runs with -checkblockindex=0: m_best_header (reported as
            # "headers") must not sit below a block that is not marked invalid.
            best_header_height = node.getblockchaininfo()["headers"]
            tips = {t["hash"]: t for t in node.getchaintips()}
            entry = tips.get(racing.hash_hex)
            if entry is not None and entry["status"] != "invalid" and best_header_height < entry["height"]:
                raise AssertionError(
                    f"attempt {attempt}: m_best_header at height {best_header_height} is below "
                    f"non-failed header {racing.hash_hex} at height {entry['height']}")

            # Restore for the next attempt: the racing header becomes the new fork tip,
            # and one more block on the active chain puts it a block ahead again.
            node.reconsiderblock(tip_hash)
            assert_equal(node.getbestblockhash(), tip_hash)
            fork_tip = racing
            fork_height = tip_height
            self.generatetodescriptor(node, 1, ADDRESS_BCRT1_UNSPENDABLE_DESCRIPTOR, sync_fun=self.no_op)

    def run_test(self):
        self.log.info("Make sure we repopulate setBlockIndexCandidates after InvalidateBlock:")
        self.log.info("Mine 4 blocks on Node 0")
        self.generate(self.nodes[0], 4, sync_fun=self.no_op)
        assert_equal(self.nodes[0].getblockcount(), 4)
        besthash_n0 = self.nodes[0].getbestblockhash()

        self.log.info("Mine competing 6 blocks on Node 1")
        self.generate(self.nodes[1], 6, sync_fun=self.no_op)
        assert_equal(self.nodes[1].getblockcount(), 6)

        self.log.info("Connect nodes to force a reorg")
        self.connect_nodes(0, 1)
        self.sync_blocks(self.nodes[0:2])
        assert_equal(self.nodes[0].getblockcount(), 6)

        # Add a header to the tip of node 0 without submitting the block. This shouldn't
        # affect results since this chain will be invalidated next.
        tip = self.nodes[0].getbestblockhash()
        block_time = self.nodes[0].getblock(self.nodes[0].getbestblockhash())['time'] + 1
        block = create_block(int(tip, 16), height=self.nodes[0].getblockcount(), ntime=block_time, version=4)
        block.solve()
        self.nodes[0].submitheader(block.serialize().hex())
        assert_equal(self.nodes[0].getblockchaininfo()["headers"], self.nodes[0].getblockchaininfo()["blocks"] + 1)

        self.log.info("Invalidate block 2 on node 0 and verify we reorg to node 0's original chain")
        badhash = self.nodes[1].getblockhash(2)
        self.nodes[0].invalidateblock(badhash)
        assert_equal(self.nodes[0].getblockcount(), 4)
        assert_equal(self.nodes[0].getbestblockhash(), besthash_n0)
        # Should report consistent blockchain info
        assert_equal(self.nodes[0].getblockchaininfo()["headers"], self.nodes[0].getblockchaininfo()["blocks"])

        self.log.info("Reconsider block 6 on node 0 again and verify that the best header is set correctly")
        self.nodes[0].reconsiderblock(tip)
        assert_equal(self.nodes[0].getblockchaininfo()["headers"], self.nodes[0].getblockchaininfo()["blocks"] + 1)

        self.log.info("Invalidate block 2 on node 0 and verify we reorg to node 0's original chain again")
        self.nodes[0].invalidateblock(badhash)
        assert_equal(self.nodes[0].getblockcount(), 4)
        assert_equal(self.nodes[0].getbestblockhash(), besthash_n0)
        assert_equal(self.nodes[0].getblockchaininfo()["headers"], self.nodes[0].getblockchaininfo()["blocks"])

        self.log.info("Make sure we won't reorg to a lower work chain:")
        self.connect_nodes(1, 2)
        self.log.info("Sync node 2 to node 1 so both have 6 blocks")
        self.sync_blocks(self.nodes[1:3])
        assert_equal(self.nodes[2].getblockcount(), 6)
        self.log.info("Invalidate block 5 on node 1 so its tip is now at 4")
        self.nodes[1].invalidateblock(self.nodes[1].getblockhash(5))
        assert_equal(self.nodes[1].getblockcount(), 4)
        self.log.info("Invalidate block 3 on node 2, so its tip is now 2")
        self.nodes[2].invalidateblock(self.nodes[2].getblockhash(3))
        assert_equal(self.nodes[2].getblockcount(), 2)
        self.log.info("..and then mine a block")
        self.generate(self.nodes[2], 1, sync_fun=self.no_op)
        self.log.info("Verify all nodes are at the right height")
        self.wait_until(lambda: self.nodes[2].getblockcount() == 3, timeout=5)
        self.wait_until(lambda: self.nodes[0].getblockcount() == 4, timeout=5)
        self.wait_until(lambda: self.nodes[1].getblockcount() == 4, timeout=5)

        self.log.info("Verify that ancestors can become chain tip candidates when we reconsider blocks")
        # Invalidate node0's current chain (1' -> 2' -> 3' -> 4') so that we don't reorg back to it in this test
        badhash = self.nodes[0].getblockhash(1)
        self.nodes[0].invalidateblock(badhash)
        # Reconsider the tip so that node0's chain becomes this chain again : 1 -> 2 -> 3 -> 4 -> 5 -> 6 -> header 7
        self.nodes[0].reconsiderblock(tip)
        blockhash_3 = self.nodes[0].getblockhash(3)
        blockhash_4 = self.nodes[0].getblockhash(4)
        blockhash_6 = self.nodes[0].getblockhash(6)
        assert_equal(self.nodes[0].getbestblockhash(), blockhash_6)

        # Invalidate block 4 so that chain becomes : 1 -> 2 -> 3
        self.nodes[0].invalidateblock(blockhash_4)
        assert_equal(self.nodes[0].getbestblockhash(), blockhash_3)
        assert_equal(self.nodes[0].getblockchaininfo()['blocks'], 3)
        assert_equal(self.nodes[0].getblockchaininfo()['headers'], 3)

        # Reconsider the header
        self.nodes[0].reconsiderblock(block.hash_hex)
        # Since header doesn't have block data, it can't be chain tip
        # Check if it's possible for an ancestor (with block data) to be the chain tip
        assert_equal(self.nodes[0].getbestblockhash(), blockhash_6)
        assert_equal(self.nodes[0].getblockchaininfo()['blocks'], 6)
        assert_equal(self.nodes[0].getblockchaininfo()['headers'], 7)

        self.log.info("Verify that we reconsider all ancestors as well")
        blocks = self.generatetodescriptor(self.nodes[1], 10, ADDRESS_BCRT1_UNSPENDABLE_DESCRIPTOR, sync_fun=self.no_op)
        assert_equal(self.nodes[1].getbestblockhash(), blocks[-1])
        # Invalidate the two blocks at the tip
        self.nodes[1].invalidateblock(blocks[-1])
        self.nodes[1].invalidateblock(blocks[-2])
        assert_equal(self.nodes[1].getbestblockhash(), blocks[-3])
        # Reconsider only the previous tip
        self.nodes[1].reconsiderblock(blocks[-1])
        # Should be back at the tip by now
        assert_equal(self.nodes[1].getbestblockhash(), blocks[-1])

        self.log.info("Verify that we reconsider all descendants")
        blocks = self.generatetodescriptor(self.nodes[1], 10, ADDRESS_BCRT1_UNSPENDABLE_DESCRIPTOR, sync_fun=self.no_op)
        assert_equal(self.nodes[1].getbestblockhash(), blocks[-1])
        # Invalidate the two blocks at the tip
        self.nodes[1].invalidateblock(blocks[-2])
        self.nodes[1].invalidateblock(blocks[-4])
        assert_equal(self.nodes[1].getbestblockhash(), blocks[-5])
        # Reconsider only the previous tip
        self.nodes[1].reconsiderblock(blocks[-4])
        # Should be back at the tip by now
        assert_equal(self.nodes[1].getbestblockhash(), blocks[-1])
        # Should report consistent blockchain info
        assert_equal(self.nodes[1].getblockchaininfo()["headers"], self.nodes[1].getblockchaininfo()["blocks"])

        self.log.info("Verify that invalidating an unknown block throws an error")
        assert_raises_rpc_error(-5, "Block not found", self.nodes[1].invalidateblock, "00" * 32)
        assert_equal(self.nodes[1].getbestblockhash(), blocks[-1])

        if self.options.race_attempts:
            self.test_best_header_race(self.options.race_attempts)

if __name__ == '__main__':
    InvalidateTest(__file__).main()
