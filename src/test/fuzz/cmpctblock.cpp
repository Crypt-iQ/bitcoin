// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addrman.h>
#include <blockencodings.h>
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <net.h>
#include <net_processing.h>
#include <netmessagemaker.h>
#include <node/blockstorage.h>
#include <node/miner.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <protocol.h>
#include <script/script.h>
#include <sync.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/fuzz/util/net.h>
#include <test/util/mining.h>
#include <test/util/net.h>
#include <test/util/random.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <test/util/txmempool.h>
#include <test/util/validation.h>
#include <txmempool.h>
#include <uint256.h>
#include <util/check.h>
#include <util/time.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>

#include <boost/multi_index/detail/hash_index_iterator.hpp>
#include <boost/operators.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

TestingSetup* g_setup;

//! Fee each created tx will pay.
const CAmount AMOUNT_FEE{1000};
//! Cached coinbases that each iteration can copy and use.
std::vector<COutPoint> g_mature_coinbase;
//! Constant value used to create valid headers.
uint32_t g_nBits;
//! One for each block the fuzzer generates.
struct BlockInfo {
    std::shared_ptr<CBlock> block;
    uint256 hash;
    uint32_t height;
};
//! Used to access prefilledtxn and shorttxids.
class FuzzedCBlockHeaderAndShortTxIDs : public CBlockHeaderAndShortTxIDs
{
    using CBlockHeaderAndShortTxIDs::CBlockHeaderAndShortTxIDs;

public:
    void AddPrefilledTx(PrefilledTransaction&& prefilledtx)
    {
        prefilledtxn.push_back(std::move(prefilledtx));
    }

    void EraseShortTxIDs(size_t index)
    {
        shorttxids.erase(shorttxids.begin() + index);
    }
};

void ResetChainmanAndMempool(TestingSetup& setup)
{
    SetMockTime(Params().GenesisBlock().Time());

    bilingual_str error{};
    setup.m_node.mempool.reset();
    setup.m_node.mempool = std::make_unique<CTxMemPool>(MemPoolOptionsForTest(setup.m_node), error);
    Assert(error.empty());

    setup.m_node.chainman.reset();
    setup.m_make_chainman();
    setup.LoadVerifyActivateChainstate();

    node::BlockAssembler::Options options;
    options.coinbase_output_script = P2WSH_OP_TRUE;
    options.include_dummy_extranonce = true;

    g_mature_coinbase.clear();

    for (int i = 0; i < 2 * COINBASE_MATURITY; ++i) {
        COutPoint prevout{MineBlock(setup.m_node, options)};
        if (i < COINBASE_MATURITY) {
            g_mature_coinbase.push_back(prevout);
        }
    }

    setup.m_node.validation_signals->SyncWithValidationInterfaceQueue();
}

} // namespace

extern void MakeRandDeterministicDANGEROUS(const uint256& seed) noexcept;

void initialize_cmpctblock()
{
    static const auto testing_setup = MakeNoLogFileContext<TestingSetup>();
    g_setup = testing_setup.get();
    g_nBits = Params().GenesisBlock().nBits;
    ResetChainmanAndMempool(*g_setup);
}

FUZZ_TARGET(cmpctblock, .init = initialize_cmpctblock)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    SetMockTime(1610000000);

    auto setup = g_setup;
    auto& mempool = *setup->m_node.mempool;
    auto& chainman = static_cast<TestChainstateManager&>(*setup->m_node.chainman);
    chainman.ResetIbd();
    chainman.DisableNextWrite();
    const size_t initial_index_size{WITH_LOCK(chainman.GetMutex(), return chainman.BlockIndex().size())};

    AddrMan addrman{*setup->m_node.netgroupman, /*deterministic=*/true, /*consistency_check_ratio=*/0};
    auto& connman = *static_cast<ConnmanTestMsg*>(setup->m_node.connman.get());
    auto peerman = PeerManager::make(connman, addrman,
                                     /*banman=*/nullptr, chainman,
                                     mempool, *setup->m_node.warnings,
                                     PeerManager::Options{
                                         .deterministic_rng = true,
                                     });
    connman.SetMsgProc(peerman.get());

    setup->m_node.validation_signals->RegisterValidationInterface(peerman.get());
    setup->m_node.validation_signals->SyncWithValidationInterfaceQueue();

    LOCK(NetEventsInterface::g_msgproc_mutex);

    std::vector<CNode*> peers;
    for (int i = 0; i < 4; ++i) {
        peers.push_back(ConsumeNodeAsUniquePtr(fuzzed_data_provider, i).release());
        CNode& p2p_node = *peers.back();
        FillNode(fuzzed_data_provider, connman, p2p_node);
        connman.AddTestNode(p2p_node);
    }

    // Stores blocks generated this iteration.
    std::vector<BlockInfo> info;

    // Coinbase UTXOs for this iteration.
    std::vector<COutPoint> mature_coinbase = g_mature_coinbase;

    const uint64_t initial_sequence{WITH_LOCK(mempool.cs, return mempool.GetSequence())};

    const CCoinsViewMemPool amount_view{WITH_LOCK(::cs_main, return &chainman.ActiveChainstate().CoinsTip()), mempool};

    auto create_tx = [&]() -> CTransactionRef {
        CMutableTransaction tx_mut;
        tx_mut.version = CTransaction::CURRENT_VERSION;
        tx_mut.nLockTime = fuzzed_data_provider.ConsumeBool() ? 0 : fuzzed_data_provider.ConsumeIntegral<uint32_t>();

        // If the mempool is non-empty, choose a mempool outpoint. Otherwise, choose a coinbase.
        COutPoint outpoint;
        unsigned long mempool_size = mempool.size();
        if (fuzzed_data_provider.ConsumeBool() && mempool_size != 0) {
            size_t random_idx = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, mempool_size - 1);
            LOCK(mempool.cs);
            outpoint = COutPoint(mempool.txns_randomized[random_idx].second->GetSharedTx()->GetHash(), 0);
        } else if (mature_coinbase.size() != 0) {
            auto pop = mature_coinbase.begin();
            std::advance(pop, fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, mature_coinbase.size() - 1));
            outpoint = *pop;
            mature_coinbase.erase(pop);
        } else {
            // We have no utxos available to make a transaction.
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

        const CAmount amount_in = Assert(amount_view.GetCoin(outpoint))->out.nValue;
        const CAmount amount_out = amount_in - AMOUNT_FEE;
        tx_mut.vout.emplace_back(amount_out, P2WSH_OP_TRUE);

        auto tx = MakeTransactionRef(tx_mut);
        return tx;
    };

    auto create_block = [&]() {
        uint256 prev;
        uint32_t height;

        if (fuzzed_data_provider.ConsumeBool() || info.size() == 0) {
            LOCK(cs_main);
            prev = chainman.ActiveChain().Tip()->GetBlockHash();
            height = chainman.ActiveChain().Height() + 1;
        } else {
            size_t index = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, info.size() - 1);
            prev = info[index].hash;
            height = info[index].height + 1;
        }

        const auto new_time = WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip()->GetMedianTimePast() + 1);

        CBlockHeader header;
        header.nNonce = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
        header.hashPrevBlock = prev;
        header.nBits = g_nBits;
        header.nTime = new_time;
        header.nVersion = fuzzed_data_provider.ConsumeIntegral<int32_t>();

        std::shared_ptr<CBlock> block = std::make_shared<CBlock>();
        *block = header;

        CMutableTransaction coinbase_tx;
        coinbase_tx.vin.resize(1);
        coinbase_tx.vin[0].prevout.SetNull();
        coinbase_tx.vin[0].scriptSig = CScript() << height << OP_0;
        coinbase_tx.vout.resize(1);
        coinbase_tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
        coinbase_tx.vout[0].nValue = COIN;
        block->vtx.push_back(MakeTransactionRef(coinbase_tx));

        const auto mempool_size = mempool.size();
        if (fuzzed_data_provider.ConsumeBool() && mempool_size != 0) {
            // Add txns from the mempool. Since we do not include parents, it may be an invalid block.
            size_t num_txns = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, mempool_size);
            size_t random_idx = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, mempool_size - 1);

            LOCK(mempool.cs);
            for (size_t i = random_idx; i < random_idx + num_txns; ++i) {
                CTransactionRef mempool_tx = mempool.txns_randomized[i % mempool_size].second->GetSharedTx();
                block->vtx.push_back(mempool_tx);
            }
        }

        // Create and add (possibly invalid) txns that are not in the mempool.
        if (fuzzed_data_provider.ConsumeBool()) {
            size_t new_txns = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 10);
            for (size_t i = 0; i < new_txns; ++i) {
                CTransactionRef non_mempool_tx = create_tx();
                if (non_mempool_tx != nullptr) {
                    block->vtx.push_back(non_mempool_tx);
                }
            }
        }

        CBlockIndex* pindexPrev{WITH_LOCK(::cs_main, return chainman.m_blockman.LookupBlockIndex(prev))};
        chainman.GenerateCoinbaseCommitment(*block, pindexPrev);

        bool mutated;
        block->hashMerkleRoot = BlockMerkleRoot(*block, &mutated);
        FinalizeHeader(*block, chainman);

        BlockInfo block_info;
        block_info.block = block;
        block_info.hash = block->GetHash();
        block_info.height = height;

        return block_info;
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
                    BlockInfo block_info = create_block();
                    cblock = block_info.block;
                    info.push_back(block_info);
                }

                uint64_t nonce = fuzzed_data_provider.ConsumeIntegral<uint64_t>();
                FuzzedCBlockHeaderAndShortTxIDs cmpctblock(*cblock, nonce);

                size_t num_txs = cblock->vtx.size();
                if (fuzzed_data_provider.ConsumeBool() || num_txs == 1) {
                    CBlockHeaderAndShortTxIDs base_cmpctblock = cmpctblock;
                    net_msg = NetMsg::Make(NetMsgType::CMPCTBLOCK, base_cmpctblock);
                    return;
                }

                int prev_idx = 0;
                size_t num_erased = 0;

                for (size_t i = 1; i < num_txs; ++i) {
                    if (fuzzed_data_provider.ConsumeBool()) continue;

                    uint16_t prefill_idx = i - prev_idx - 1;
                    prev_idx = i;
                    CTransactionRef txref = cblock->vtx[i];
                    PrefilledTransaction prefilledtx = {/*index=*/prefill_idx, txref};
                    cmpctblock.AddPrefilledTx(std::move(prefilledtx));

                    // Remove from shorttxids since we've prefilled. Subtract however many txs have been prefilled.
                    cmpctblock.EraseShortTxIDs(i - 1 - num_erased);
                    ++num_erased;
                }

                CBlockHeaderAndShortTxIDs base_cmpctblock = cmpctblock;
                net_msg = NetMsg::Make(NetMsgType::CMPCTBLOCK, base_cmpctblock);
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
                const BlockInfo& block_info = info[index];
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
                block.vtx.clear(); // No tx in HEADERS.
                std::vector<CBlock> headers;
                headers.emplace_back(block);

                net_msg = NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(headers));
            },
            [&]() {
                // Send a sendcmpct message, optionally setting hb mode.
                bool hb = fuzzed_data_provider.ConsumeBool();
                net_msg = NetMsg::Make(NetMsgType::SENDCMPCT, /*high_bandwidth=*/hb, /*version=*/CMPCTBLOCKS_VERSION);
            },
            [&]() {
                // Mine a block, but don't send it.
                BlockInfo block_info = create_block();
                info.push_back(block_info);
                set_net_msg = false;
            },
            [&]() {
                // Send a transaction.
                CTransactionRef tx = create_tx();
                if (tx == nullptr) {
                    set_net_msg = false;
                    return;
                }

                net_msg = NetMsg::Make(NetMsgType::TX, TX_WITH_WITNESS(*tx));
            },
            [&]() {
                // Set mock time randomly or to tip's time.
                if (fuzzed_data_provider.ConsumeBool()) {
                    SetMockTime(ConsumeTime(fuzzed_data_provider));
                } else {
                    const uint64_t tip_time = WITH_LOCK(::cs_main, return chainman.ActiveChain().Tip()->GetBlockTime());
                    SetMockTime(tip_time);
                }

                set_net_msg = false;
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

            more_work = connman.ProcessMessagesOnce(random_node);
            peerman->SendMessages(&random_node);
        }
    }

    setup->m_node.validation_signals->SyncWithValidationInterfaceQueue();
    connman.StopNodes();
    setup->m_node.validation_signals->UnregisterAllValidationInterfaces();

    const size_t end_index_size{WITH_LOCK(chainman.GetMutex(), return chainman.BlockIndex().size())};
    const uint64_t end_sequence{WITH_LOCK(mempool.cs, return mempool.GetSequence())};

    if (initial_index_size != end_index_size || initial_sequence != end_sequence) {
        MakeRandDeterministicDANGEROUS(uint256::ZERO);
        ResetChainmanAndMempool(*g_setup);
    }
}
