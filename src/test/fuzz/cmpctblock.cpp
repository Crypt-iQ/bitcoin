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
#include <test/fuzz/util.h>
#include <test/fuzz/util/mempool.h>
#include <test/fuzz/util/net.h>
#include <test/util/mining.h>
#include <test/util/net.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <test/util/txmempool.h>
#include <test/util/validation.h>
#include <util/time.h>
#include <validationinterface.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace {

const TestingSetup* g_setup;
std::vector<COutPoint> g_mature_coinbase;
//std::vector<COutPoint> g_immature_coinbase;

//! One for each block the fuzzer generates.
struct BlockInfo {
    std::shared_ptr<CBlock> block;
    uint256 hash;
    uint32_t height;
};

uint32_t g_nBits;
uint32_t g_height;
uint256 g_tip;

std::unique_ptr<CTxMemPool> g_mempool;

} // namespace

// TODO: Move MakeEphemeralMempool out of package_eval.cpp so we can use it here.
std::unique_ptr<CTxMemPool> MakeEphemeralMempool1(const node::NodeContext& node)
{
    // Take the default options for tests...
    CTxMemPool::Options mempool_opts{MemPoolOptionsForTest(node)};

    mempool_opts.check_ratio = 1;

    // Require standardness rules otherwise ephemeral dust is no-op
    mempool_opts.require_standard = true;

    // And set minrelay to 0 to allow ephemeral parent tx even with non-TRUC
    mempool_opts.min_relay_feerate = CFeeRate(0);

    bilingual_str error;
    // ...and construct a CTxMemPool from it
    auto mempool{std::make_unique<CTxMemPool>(std::move(mempool_opts), error)};
    Assert(error.empty());
    return mempool;
}

void initialize_cmpctblock() {
    // TestingSetup, mine block, store coinbase

    static const auto testing_setup = MakeNoLogFileContext<const TestingSetup>();
    g_setup = testing_setup.get();

    node::BlockAssembler::Options options;
    options.coinbase_output_script = P2WSH_OP_TRUE;

    for (int i = 0; i < 2 * COINBASE_MATURITY; ++i) {
        COutPoint prevout{MineBlock(g_setup->m_node, options)};
        if (i < COINBASE_MATURITY) {
            g_mature_coinbase.push_back(prevout);
        }
    }
    g_setup->m_node.validation_signals->SyncWithValidationInterfaceQueue();

    g_nBits = Params().GenesisBlock().nBits;

    g_setup->m_node.validation_signals->RegisterValidationInterface(g_setup->m_node.peerman.get());
    g_setup->m_node.validation_signals->SyncWithValidationInterfaceQueue();
    WITH_LOCK(::cs_main, g_tip = g_setup->m_node.chainman->ActiveChain().Tip()->GetBlockHash());
    WITH_LOCK(::cs_main, g_height = g_setup->m_node.chainman->ActiveChain().Height());
    auto& chainman = static_cast<TestChainstateManager&>(*g_setup->m_node.chainman);
    chainman.ResetIbd();

    auto& chainstate{static_cast<DummyChainState&>(chainman.ActiveChainstate())};
    g_mempool = MakeEphemeralMempool1(g_setup->m_node);
    chainstate.SetMempool(g_mempool.get());
}

FUZZ_TARGET(cmpctblock, .init=initialize_cmpctblock)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    // Set time so that we might be close to the tip's time.
    SetMockTime(ConsumeTime(fuzzed_data_provider));
 
    LOCK(NetEventsInterface::g_msgproc_mutex); 

    std::vector<CNode*> peers;
    auto& connman = *static_cast<ConnmanTestMsg*>(g_setup->m_node.connman.get()); 
    for (int i = 0; i < 3; ++i) {
        peers.push_back(ConsumeNodeAsUniquePtr(fuzzed_data_provider, i).release());
        CNode& p2p_node = *peers.back();
        FillNode(fuzzed_data_provider, connman, p2p_node);
        connman.AddTestNode(p2p_node);
    }

    // Stores blocks generated this iteration.
    std::vector<BlockInfo> info;

    const CCoinsViewMemPool amount_view{WITH_LOCK(::cs_main, return &g_setup->m_node.chainman->ActiveChainstate().CoinsTip()), *g_mempool.get()};
    const auto GetAmount = [&](const COutPoint& outpoint) {
        auto coin{amount_view.GetCoin(outpoint).value()};
        return coin.out.nValue;
    };

    auto create_tx = [&]() -> CTransactionRef {
        CMutableTransaction tx_mut;
        tx_mut.version = CTransaction::CURRENT_VERSION;
        tx_mut.nLockTime = fuzzed_data_provider.ConsumeBool() ? 0 : fuzzed_data_provider.ConsumeIntegral<uint32_t>();

        // If the mempool is non-empty, choose a mempool outpoint. Otherwise, choose a coinbase.
        COutPoint outpoint;
        if (g_mempool->size() != 0) {
            LOCK(g_mempool->cs);
            outpoint = COutPoint(g_mempool->txns_randomized[0]->GetHash(), 0);
        } else if (g_mature_coinbase.size() != 0) {
            auto pop = g_mature_coinbase.begin();
            std::advance(pop, fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, g_mature_coinbase.size() - 1));
            outpoint = *pop;
            g_mature_coinbase.erase(pop);
        } else {
            // We have no utxos available to make a transaction.
            // TODO: Make orphans?
            return nullptr;
        }

        const auto sequence = ConsumeSequence(fuzzed_data_provider);
        const auto script_sig = CScript{};
        const auto script_wit_stack = std::vector<std::vector<uint8_t>>{WITNESS_STACK_ELEM_OP_TRUE};
        CTxIn in;
        in.prevout = outpoint;
        in.nSequence = sequence;
        in.scriptSig = script_sig;
        in.scriptWitness.stack = script_wit_stack;
        tx_mut.vin.push_back(in);

        const CAmount amount_in = GetAmount(outpoint);
        const CAmount amount_fee = 1000;
        const CAmount amount_out = amount_in - amount_fee;
        tx_mut.vout.emplace_back(amount_out, P2WSH_OP_TRUE);

        auto tx = MakeTransactionRef(tx_mut);
        return tx;
    };

    auto create_block = [&]() {
        uint256 prev;
        uint32_t height;

        if (fuzzed_data_provider.ConsumeBool() || info.size() == 0) {
            prev = g_tip;
            height = g_height + 1;
        } else {
            size_t index = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, info.size() - 1);
            prev = info[index].hash;
            height = info[index].height + 1;
        }

        const auto new_time = WITH_LOCK(::cs_main, return g_setup->m_node.chainman->ActiveChain().Tip()->GetMedianTimePast() + 1);
        // TODO: Calculate nBits or disable.

        CBlockHeader header;
        header.nNonce = 0;
        header.hashPrevBlock = prev;
        header.nBits = g_nBits;
        header.nTime = new_time;
        header.nVersion = fuzzed_data_provider.ConsumeIntegral<int32_t>();

        std::shared_ptr<CBlock> block = std::make_shared<CBlock>();
        *block = header;

        CMutableTransaction coinbaseTx;
        coinbaseTx.vin.resize(1);
        coinbaseTx.vin[0].prevout.SetNull();
        coinbaseTx.vout.resize(1);
        coinbaseTx.vout[0].scriptPubKey = CScript() << OP_TRUE;
        coinbaseTx.vout[0].nValue = COIN;
        coinbaseTx.vin[0].scriptSig = CScript() << height << OP_0;
        block->vtx.push_back(MakeTransactionRef(coinbaseTx));

        // Sometimes add a txn from mempool.
        if (fuzzed_data_provider.ConsumeBool() && g_mempool->size() != 0) {
            LOCK(g_mempool->cs);
            CTransactionRef tx = g_mempool->txns_randomized[0];
            block->vtx.push_back(tx);
        }

        bool mutated;
        block->hashMerkleRoot = BlockMerkleRoot(*block, &mutated);
        auto& chainman = static_cast<TestChainstateManager&>(*g_setup->m_node.chainman);
        FinalizeHeader(header, chainman);

        BlockInfo blockinfo;
        blockinfo.block = block;
        blockinfo.hash = block->GetHash();
        blockinfo.height = height;

        return blockinfo;
    };

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 1000)
    {
        CSerializedNetMsg net_msg;
        bool set_net_msg = true;

        CallOneOf(
            fuzzed_data_provider,
            [&]() {
                // Send a compact block.
                std::shared_ptr<CBlock> cblock;

                // Pick an existing block or create a new block.
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
                    net_msg = NetMsg::Make(NetMsgType::CMPCTBLOCK, cmpctBlock);
                    return;
                }

                int prev_idx = 0;

                for (int i = 1; i < num_txs; ++i) {
                    if (fuzzed_data_provider.ConsumeBool()) continue;

                    uint16_t prefill_idx = i - prev_idx - 1;
                    prev_idx = i;
                    CTransactionRef txref = cblock->vtx[i];
                    PrefilledTransaction prefilledtx = {/*index=*/prefill_idx, txref};
                    cmpctBlock.prefilledtxn.push_back(std::move(prefilledtx));

                    // Remove from shorttxids
                    cmpctBlock.shorttxids.erase(cmpctBlock.shorttxids.begin() + i - 1);
                }

                net_msg = NetMsg::Make(NetMsgType::CMPCTBLOCK, cmpctBlock);
            },
            [&]() {
                // Send a blocktxn message for an existing block (if one exists).
                size_t num_blocks = info.size();
                if (num_blocks == 0) {
                    set_net_msg = false;
                    return;
                }

                // Fetch an existing block and randomly choose transactions to send over.
                size_t index = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, num_blocks - 1);
                BlockInfo block_info = info[index];
                BlockTransactions block_txn;
                block_txn.blockhash = block_info.hash;
                std::shared_ptr<CBlock> cblock = block_info.block;

                size_t num_txs = cblock->vtx.size();
                if (num_txs > 1) {
                    for (size_t i = 1; i < num_txs; i++) {
                        if (fuzzed_data_provider.ConsumeBool()) continue;

                        block_txn.txn.push_back(cblock->vtx[i]);
                    }
                }

                net_msg = NetMsg::Make(NetMsgType::BLOCKTXN, block_txn);
            },
            [&]() {
                // Send a headers message for an existing block (if one exists).
                size_t num_blocks = info.size();
                if (num_blocks == 0) {
                    set_net_msg = false;
                    return;
                }

                // Choose an existing block and send a HEADERS message for it.
                size_t index = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, num_blocks - 1);
                CBlock block = *info[index].block;
                std::vector<CBlock> headers;
                headers.push_back(block);

                net_msg = NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(headers));
            },
            [&]() {
                // Send a sendcmpct message, optionally setting hb mode.
                bool hb = fuzzed_data_provider.ConsumeBool();

                // TODO: Extract CMPCTBLOCKS_VERSION from net_processing.cpp
                net_msg = NetMsg::Make(NetMsgType::SENDCMPCT, /*high_bandwidth=*/hb, /*version=*/uint64_t(2));
            },
            [&]() {
                // Mine a block, but don't send it over p2p.
                BlockInfo blockinfo = create_block();
                info.push_back(blockinfo);
                set_net_msg = false;
            },
            [&]() {
                // Send a txn over p2p.
                CTransactionRef tx = create_tx();
                if (tx == nullptr) {
                    set_net_msg = false;
                    return;
                }

                net_msg = NetMsg::Make(NetMsgType::TX, TX_WITH_WITNESS(*tx));
            });

        if (!set_net_msg) {
            continue;
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
}
