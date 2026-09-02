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
        parser.add_argument("--best-header-attempts", type=int, default=0,
                            help="Attempts for the invalid-m_best_header race test")
        parser.add_argument("--reconsider-attempts", type=int, default=0,
                            help="Attempts for the concurrent reconsiderblock race test")

    def test_invalid_best_header_race(self, attempts, depth=30):
        """Flag a highpow_outofchain_headers entry while the disconnect loop is running.

        The candidate scan in the disconnect loop assigns m_best_header without
        rechecking BLOCK_FAILED_VALID. The snapshot filtered on that flag once, before
        cs_main was ever released, so a block flagged during a gap is still in the map
        and still eligible. AcceptBlock calls InvalidBlockFound under cs_main only
        (validation.cpp:4379), so submitting an invalid full block for a known header
        does the flagging.

        The candidate is a sibling of the block being invalidated: same height, so its
        work exceeds pindex->pprev (it is in the snapshot) but is below every new_tip
        until the final iteration. That means it is only selected on the last
        disconnect, and any of the ~depth gaps before that is a winning window.

        A win trips assert(!(m_best_header->nStatus & BLOCK_FAILED_VALID)) at the top of
        ChainstateManager::CheckBlockIndex. Run with -checkblockindex=0 for the softer
        detector below instead of a crash.
        """
        self.log.info(f"Race an invalidated candidate into m_best_header ({attempts} attempts)")
        node = self.nodes[2]
        self.disconnect_nodes(1, 2)
        racer = node.create_new_rpc_connection()
        racer.getblockcount()  # prime the connection
        self.generatetodescriptor(node, depth + 5, ADDRESS_BCRT1_UNSPENDABLE_DESCRIPTOR, sync_fun=self.no_op)

        for attempt in range(attempts):
            height = node.getblockcount()
            target_height = height - depth
            target_hash = node.getblockhash(target_height)
            parent_hash = node.getblockhash(target_height - 1)
            parent_time = node.getblock(parent_hash)["time"]

            # The inflated coinbase height makes the full block fail
            # ContextualCheckBlock with bad-txns-nonfinal (create_coinbase sets
            # nLockTime = height - 1, so IsFinalTx rejects before the BIP34 check).
            # That is BLOCK_CONSENSUS, not BLOCK_MUTATED, which is what
            # InvalidBlockFound requires in order to flag the block.
            # ntime varies per attempt so each sibling has a distinct hash.
            sibling = create_block(int(parent_hash, 16),
                                   height=target_height + 1000,
                                   ntime=parent_time + 1 + attempt)
            sibling.solve()
            node.submitheader(sibling.serialize().hex())
            sibling_hex = sibling.serialize().hex()

            result = {}
            start = threading.Event()
            # Lower bound keeps the submission from landing before the snapshot is
            # taken, which would exclude the sibling from the map and waste the attempt.
            delay = random.uniform(0.0005, 0.01)

            def submit():
                start.wait()
                time.sleep(delay)
                result["reject"] = racer.submitblock(sibling_hex)

            thread = threading.Thread(target=submit)
            thread.start()
            start.set()
            try:
                node.invalidateblock(target_hash)
            except Exception as e:
                thread.join()
                raise AssertionError(
                    f"attempt {attempt}: node stopped responding during invalidateblock, "
                    f"check debug.log for the CheckBlockIndex assertion ({e})")
            thread.join()
            # Confirms the sibling really was flagged, so the attempt was a real trial.
            assert_equal(result["reject"], "bad-txns-nonfinal")

            best_header_height = node.getblockchaininfo()["headers"]
            tips = {tip["hash"]: tip for tip in node.getchaintips()}
            entry = tips.get(sibling.hash_hex)
            if entry is not None and entry["status"] == "invalid" and best_header_height == entry["height"]:
                raise AssertionError(
                    f"attempt {attempt}: m_best_header is at height {best_header_height}, "
                    f"the height of invalid block {sibling.hash_hex}")

            node.reconsiderblock(target_hash)
            assert_equal(node.getblockcount(), height)

    def test_reconsiderblock_race(self, attempts, depth=30, racers=4):
        """Run ResetBlockFailureFlags inside InvalidateBlock's disconnect loop.

        ReconsiderBlock in rpc/blockchain.cpp takes only chainman.GetMutex() for
        ResetBlockFailureFlags, then blocks on m_chainstate_mutex in ActivateBestChain.
        The disconnect loop releases cs_main every iteration, so a reconsider thread can
        acquire it in any gap.

        ResetBlockFailureFlags clears BLOCK_FAILED_VALID on both descendants and
        ancestors of its argument, so reconsiderblock on the old tip clears every block
        the loop has flagged so far. The next iteration then flags one block lower,
        leaving already-unflagged descendants above a flagged block. That trips
        assert(pindex->nStatus & BLOCK_FAILED_VALID) at validation.cpp:5310.

        Landing anywhere in the loop except the final gap is a win, so this needs far
        fewer attempts than the other race. Several threads with staggered delays are
        used because each one blocks until invalidateblock returns and so gets one shot.
        """
        self.log.info(f"Race reconsiderblock against invalidateblock ({attempts} attempts)")
        node = self.nodes[2]
        self.disconnect_nodes(1, 2)
        conns = [node.create_new_rpc_connection() for _ in range(racers)]
        for conn in conns:
            conn.getblockcount()  # prime the connections
        self.generatetodescriptor(node, depth + 5, ADDRESS_BCRT1_UNSPENDABLE_DESCRIPTOR, sync_fun=self.no_op)

        for attempt in range(attempts):
            height = node.getblockcount()
            tip_hash = node.getbestblockhash()
            target_hash = node.getblockhash(height - depth)

            start = threading.Event()
            errors = []

            def reconsider(conn, delay):
                start.wait()
                time.sleep(delay)
                try:
                    conn.reconsiderblock(tip_hash)
                except Exception as e:
                    errors.append(e)

            threads = [threading.Thread(target=reconsider,
                                        args=(conns[i], random.uniform(0.0005, 0.01)))
                       for i in range(racers)]
            for thread in threads:
                thread.start()
            start.set()
            try:
                node.invalidateblock(target_hash)
            except Exception as e:
                for thread in threads:
                    thread.join()
                raise AssertionError(
                    f"attempt {attempt}: node stopped responding during invalidateblock, "
                    f"check debug.log for the CheckBlockIndex assertion ({e})")
            # The reconsider threads are parked in ActivateBestChain on m_chainstate_mutex
            # until the invalidateblock above releases it, so join only now.
            for thread in threads:
                thread.join()
            assert_equal(errors, [])

            # Heuristic follow-up: if flags or candidates were left inconsistent, the
            # restore below will not bring the chain and the best header back together.
            node.reconsiderblock(target_hash)
            info = node.getblockchaininfo()
            assert_equal(info["blocks"], height)
            assert_equal(info["headers"], height)
            assert_equal(node.getbestblockhash(), tip_hash)

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

        if self.options.best_header_attempts:
            self.test_invalid_best_header_race(self.options.best_header_attempts)
        if self.options.reconsider_attempts:
            self.test_reconsiderblock_race(self.options.reconsider_attempts)

if __name__ == '__main__':
    InvalidateTest(__file__).main()
