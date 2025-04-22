// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blockencodings.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <net.h>
#include <net_processing.h>
#include <pow.h>
#include <protocol.h>
#include <script/script.h>
#include <streams.h>
#include <sync.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/snapshot_fuzz.h>
#include <test/fuzz/util.h>
#include <test/fuzz/util/net.h>
#include <test/util/mining.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <util/time.h>
#include <validationinterface.h>

#include <ios>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

// The list of possible fuzzer commands. Most of them are which protocol message a random peer should send over.
// The exception is MINE_BLOCK which mines a new block.
enum Command : uint8_t {
    CMPCTBLOCK,
    BLOCKTXN,
    HEADERS,
    SENDCMPCT,
    MINE_BLOCK,
};

// A BlockInfo is created for every block the fuzz harness generates. It contains a shared pointer to the block
// and additionally stores the block's hash and height.
struct BlockInfo {
    std::shared_ptr<CBlock> block;
    uint256 hash;
    uint32_t height;
};

// This fuzz harness attempts to exercise the compact blocks protocol logic. It mainly does so by
// creating valid headers and sending these via one of the connected peers. The fuzzer is restricted
// in where it is creating mutations because it is restricted to an enum of commands. This allows us to
// limit the mutations to specific parts such as not allowing unrelated p2p messages from being sent
// (therefore limiting the number of useless iterations) or by choosing how the CMPCTBLOCK or BLOCKTXN
// messages are structured.
static void cmpctblock(snapshot_fuzz::Fuzz& fuzz)
{
    // Initialize the slow global state setup that we want to snapshot.
    SeedRandomStateForTest(SeedRand::ZEROS);

    const TestingSetup* g_setup;
    uint256 g_tip;
    uint32_t g_nBits;
    uint32_t g_height;

    const auto testing_setup = MakeNoLogFileContext<const TestingSetup>(
        /*chain_type=*/ChainType::REGTEST,
        {.extra_args = {"-txreconciliation"}});
    
    g_setup = testing_setup.get();
    
    for (int i = 0; i < 2 * COINBASE_MATURITY; i++) {
        MineBlock(g_setup->m_node, {});
    }

    g_setup->m_node.validation_signals->RegisterValidationInterface(g_setup->m_node.peerman.get());
    g_setup->m_node.validation_signals->SyncWithValidationInterfaceQueue();

    WITH_LOCK(::cs_main, g_tip = g_setup->m_node.chainman->ActiveChain().Tip()->GetBlockHash());
    WITH_LOCK(::cs_main, g_height = g_setup->m_node.chainman->ActiveChain().Height());

    // Save the nBits so that the fuzzer does not need to guess this.
    g_nBits = Params().GenesisBlock().nBits;

    // The code in the below run(...) will execute each fuzzing iteration, using the state just prior to calling
    // run(...) as the VM snapshot point. This allows us to initiate slow global state once and restore a VM snapshot
    // each fuzzing iteration instead of having to initiate the slow global state every time for non-determinism.
    // Until the expensive setup calls have been mocked out (likely in disk access), snapshot fuzzing is a viable
    // interim solution for fuzz harnesses to achieve good code coverage, non-determinism, and speed.
    fuzz.run([&](std::span<const uint8_t> buffer) {

        FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

        ConnmanTestMsg& connman = *static_cast<ConnmanTestMsg*>(g_setup->m_node.connman.get());
        auto& chainman = static_cast<TestChainstateManager&>(*g_setup->m_node.chainman);
        SetMockTime(1610000000); // any time to successfully reset ibd
        chainman.ResetIbd();

        // Stores the current set of blocks that the fuzzer has generated this iteration.
        std::vector<BlockInfo> info;

        LOCK(NetEventsInterface::g_msgproc_mutex);

        std::vector<CNode*> peers;
        NodeId id{0};
        for (int i = 0; i < 3; i++) {
            peers.push_back(ConsumeNodeAsUniquePtr(fuzzed_data_provider, id++).release());
            CNode& p2p_node = *peers.back();

            FillNode(fuzzed_data_provider, connman, p2p_node);

            connman.AddTestNode(p2p_node);
        }

        // We set the time here so that we are close enough to the tip to accept compact blocks from the peer and
        // can bypass the CanDirectFetch check upon receipt of CMPCTBLOCK.
        const auto mock_time = ConsumeTime(fuzzed_data_provider);
        SetMockTime(mock_time);

        auto create_block = [&]() {
            CBlockHeader header;
            header.nNonce = 0;

            uint256 prev;
            uint32_t height;

            // Set hashPrevBlock to g_tip randomly some of the time and when the fuzzer hasn't yet created any blocks.
            // Set it to a random, created block the rest of the time.
            if (fuzzed_data_provider.ConsumeBool() || info.size() == 0) {
                prev = g_tip;
                height = g_height + 1;
            } else {
                size_t index = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, info.size() - 1);
                prev = info[index].hash;
                height = info[index].height + 1;
            }

            header.hashPrevBlock = prev;
            header.nBits = g_nBits;

            const auto new_time = WITH_LOCK(::cs_main, return g_setup->m_node.chainman->ActiveChain().Tip()->GetMedianTimePast() + 1);
            header.nTime = new_time;
            header.nVersion = fuzzed_data_provider.ConsumeIntegral<int32_t>();

            std::shared_ptr<CBlock> block = std::make_shared<CBlock>();
            *block = header;

            // Randomly provide a valid BIP34 coinbase. This will let the fuzzer hit cases that depend on valid blocks
            // to be processed.
            if (fuzzed_data_provider.ConsumeBool()) {
                CMutableTransaction coinbaseTx;

                coinbaseTx.vin.resize(1);
                coinbaseTx.vin[0].prevout.SetNull();
                coinbaseTx.vout.resize(1);
                coinbaseTx.vout[0].scriptPubKey = CScript() << OP_TRUE;
                coinbaseTx.vout[0].nValue = 100; // Any amount is fine for now.
                coinbaseTx.vin[0].scriptSig = CScript() << height << OP_0;

                block->vtx.push_back(MakeTransactionRef(coinbaseTx));
            } else {
                // Otherwise, just fill the block with (likely invalid) transactions.
                uint8_t num_txns = fuzzed_data_provider.ConsumeIntegralInRange<uint8_t>(1, 10);
                for (int i = 0; i < num_txns; i++) {
                    CMutableTransaction tx = ConsumeTransaction(fuzzed_data_provider, std::nullopt);
                    block->vtx.push_back(MakeTransactionRef(tx));
                }
            }

            bool mutated;
            block->hashMerkleRoot = BlockMerkleRoot(*block, &mutated);
            FinalizeHeader(header, chainman);

            BlockInfo blockinfo;
            blockinfo.block = block;
            blockinfo.hash = block->GetHash();
            blockinfo.height = height;

            return blockinfo;
        };

        LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 30)
        {
            CSerializedNetMsg net_msg;

            uint8_t fuzzed_command = fuzzed_data_provider.ConsumeIntegralInRange<uint8_t>(CMPCTBLOCK, MINE_BLOCK);
            switch (fuzzed_command) {
            case CMPCTBLOCK: {
                std::shared_ptr<CBlock> cblock;

                // Sometimes pick from an existing block and the rest of the time create a new block.
                if (fuzzed_data_provider.ConsumeBool() && info.size() != 0) {
                    size_t index = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, info.size() - 1);
                    cblock = info[index].block;
                } else {
                    BlockInfo blockinfo = create_block();
                    cblock = blockinfo.block;
                    info.push_back(blockinfo);
                }

                uint64_t nonce = fuzzed_data_provider.ConsumeIntegral<uint64_t>();
                CBlockHeaderAndShortTxIDs cmpctBlock(*cblock, nonce);

                size_t num_txs = cblock->vtx.size();
                if (fuzzed_data_provider.ConsumeBool() || num_txs == 1) {
                    // Some of the time, don't modify the compact block that the constructor makes.
                    net_msg = NetMsg::Make(NetMsgType::CMPCTBLOCK, cmpctBlock);
                    break;
                }

                // The rest of the time, populate prefilledtxns and shorttxids while keeping hashMerkleRoot the same.
                // Choose a random number of PrefilledTransaction to include, starting in-order from vtx[1].
                size_t num_prefilled = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(2, num_txs);

                for (size_t i = 1; i < num_prefilled; i++) {
                    CTransactionRef txref = cblock->vtx[i];

                    // TODO: Fuzz PrefilledTransaction index field.
                    PrefilledTransaction prefilledtx = {/*index=*/0, txref};
                    cmpctBlock.prefilledtxn.push_back(std::move(prefilledtx));
                }

                // Erase from the front of shorttxids since these transactions have been prefilled. This is hacky -- we
                // could instead introduce a new test-only constructor that dictates what transactions are prefilled.
                for (size_t i = 0; i < num_prefilled - 1; i++) {
                    cmpctBlock.shorttxids.erase(cmpctBlock.shorttxids.begin());
                }

                net_msg = NetMsg::Make(NetMsgType::CMPCTBLOCK, cmpctBlock);

                break;
            }

            case BLOCKTXN: {
                // If no blocks exist, return.
                size_t num_blocks = info.size();
                if (num_blocks == 0) {
                    break;
                }

                // Here, we'll send a BLOCKTXN message regardless if it was requested or not. We'll loop through the block's
                // transactions and pick some to provide in the message. There are no gaps in the set of transactions that we
                // send over. In the future, the fuzzer could fill in the missing transactions in a more random way.

                // Fetch a pre-existing block and determine which transactions to send over.
                size_t index = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, num_blocks - 1);

                BlockInfo block_info = info[index];

                BlockTransactions block_txn;
                block_txn.blockhash = block_info.hash;

                std::shared_ptr<CBlock> cblock = block_info.block;

                size_t num_txs = cblock->vtx.size();

                if (num_txs > 1) {
                    // If the fuzzer has sent over a CMPCTBLOCK in the same fuzzing iteration, it is possible that this BLOCKTXN
                    // may be viewed as a response to a GETBLOCKTXN. If that is the case, the fuzzer may guess the correct number
                    // of missing transactions to fill in and thus gain even more coverage when FillBlock is called.
                    //
                    // Select which txns from the block to send. Since the first prefilled txn is already filled-in at index=0,
                    // we only do this if the number of transactions in the block is greater than 1.
                    for (size_t i = 1; i < num_txs; i++) {
                        block_txn.txn.push_back(cblock->vtx[i]);
                    }
                }

                net_msg = NetMsg::Make(NetMsgType::BLOCKTXN, block_txn);

                break;
            }

            case HEADERS: {
                size_t num_blocks = info.size();
                if (num_blocks == 0) {
                    break;
                }

                // Choose a random, existing block that the fuzzer has created and send a HEADERS message for it.
                // Doing this allows us to somewhat fuzz mapBlocksInFlight and can allow the fuzzer to hit an additional
                // branch in compact-blocks processing where the block has been requested but not via compact blocks.
                size_t index = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, num_blocks - 1);
                CBlock block = *info[index].block;

                std::vector<CBlock> headers;
                headers.push_back(block);

                net_msg = NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(headers));

                break;
            }

            case SENDCMPCT: {
                bool hb = fuzzed_data_provider.ConsumeBool();

                // TODO: Extract CMPCTBLOCKS_VERSION from net_processing.cpp
                net_msg = NetMsg::Make(NetMsgType::SENDCMPCT, /*high_bandwidth=*/hb, /*version=*/uint64_t(2));

                break;
            }

            case MINE_BLOCK: {
                BlockInfo blockinfo = create_block();
                info.push_back(blockinfo);

                break;
            }
            }

            CNode& random_node = *PickValue(fuzzed_data_provider, peers);

            connman.FlushSendBuffer(random_node);
            (void)connman.ReceiveMsgFrom(random_node, std::move(net_msg));

            bool more_work{true};
            while (more_work) {
                random_node.fPauseSend = false;

                try {
                    more_work = connman.ProcessMessagesOnce(random_node);
                } catch (const std::ios_base::failure&) {
                }
                g_setup->m_node.peerman->SendMessages(&random_node);
            }
        }

        g_setup->m_node.validation_signals->SyncWithValidationInterfaceQueue();
        g_setup->m_node.connman->StopNodes();
    });
}

SNAPSHOT_FUZZ_TARGET(cmpctblock)
