// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blockencodings.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <net.h>
#include <net_processing.h>
#include <node/warnings.h>
#include <random.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/fuzz/util/net.h>
#include <test/util/mining.h>
#include <test/util/net.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <test/util/txmempool.h>
#include <test/util/validation.h>
#include <util/fs.h>
#include <validationinterface.h>

#include <memory>
#include <vector>

using namespace util::hex_literals;

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
//! Class to delete the statically-named datadir at the end of a fuzzing run.
class FuzzedDirectoryWrapper
{
private:
    fs::path staticdir;

public:
    FuzzedDirectoryWrapper(fs::path name) : staticdir(name) {}

    ~FuzzedDirectoryWrapper()
    {
        fs::remove_all(staticdir);
    }
};

void ResetChainman(TestingSetup& setup)
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

    g_mature_coinbase.clear();

    for (int i = 0; i < 2 * COINBASE_MATURITY; ++i) {
        COutPoint prevout{MineBlock(setup.m_node, options)};
        if (i < COINBASE_MATURITY) {
            g_mature_coinbase.push_back(prevout);
        }
    }

    // TODO: Remove?
    setup.m_node.validation_signals->SyncWithValidationInterfaceQueue();
}

} // namespace

extern void MakeRandDeterministicDANGEROUS(const uint256& seed) noexcept;

void initialize_cmpctblock() {
    static const auto testing_setup = MakeNoLogFileContext<TestingSetup>(
        /*chain_type=*/ChainType::REGTEST,
        {.coins_db_in_memory = true,
         .block_tree_db_in_memory = true,
         .setup_validation_interface = false,
         .setup_validation_interface_no_scheduler = true});

    g_setup = testing_setup.get();
    g_nBits = Params().GenesisBlock().nBits;

    ResetChainman(*g_setup);
}

FUZZ_TARGET(cmpctblock, .init=initialize_cmpctblock)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    auto& g_chainman = *g_setup->m_node.chainman;
    /*if (WITH_LOCK(g_chainman.GetMutex(), return g_chainman.BlockIndex().size()) != 201 ||
        g_setup->m_node.mempool->size() != 0) {

        ResetChainman(*g_setup);
    }*/

    SetMockTime(1610000000);

    // move Reset logic above to here?

    // chainman.DisableNextWrite???

    //const auto mock_start_time{1610000000};

    //node::BlockAssembler::Options options;
    //options.coinbase_output_script = P2WSH_OP_TRUE;

    /*for (int i = 0; i < 2 * COINBASE_MATURITY; ++i) {
        COutPoint prevout{MineBlock(testing_setup->m_node, options)};
        if (i < COINBASE_MATURITY) {
            g_mature_coinbase.push_back(prevout);
        }
    }*/

    //g_nBits = Params().GenesisBlock().nBits;

/*
    auto setup = g_setup.get();

    setup->m_node.validation_signals->RegisterValidationInterface(setup->m_node.peerman.get());
    setup->m_node.validation_signals->SyncWithValidationInterfaceQueue();
    auto& chainman = static_cast<TestChainstateManager&>(*setup->m_node.chainman);
    chainman.ResetIbd();
*/
    auto setup = g_setup;

    auto& chainman = static_cast<TestChainstateManager&>(*setup->m_node.chainman);
    //const auto block_index_size{WITH_LOCK(chainman.GetMutex(), return chainman.BlockIndex().size())};
    chainman.ResetIbd();

    node::Warnings warnings{};
    NetGroupManager netgroupman{{}};
    AddrMan addrman{netgroupman, /*deterministic=*/true, /*consistency_check_ratio=*/0};
    auto& connman = *static_cast<ConnmanTestMsg*>(setup->m_node.connman.get());
    auto peerman = PeerManager::make(connman, addrman,
                                     /*banman=*/nullptr, chainman,
                                     *setup->m_node.mempool, warnings,
                                     PeerManager::Options{
                                         .reconcile_txs = true,
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

    const CCoinsViewMemPool amount_view{WITH_LOCK(::cs_main, return &setup->m_node.chainman->ActiveChainstate().CoinsTip()), *setup->m_node.mempool};

    auto create_tx = [&]() -> CTransactionRef {
        CMutableTransaction tx_mut;
        tx_mut.version = CTransaction::CURRENT_VERSION;
        tx_mut.nLockTime = fuzzed_data_provider.ConsumeBool() ? 0 : fuzzed_data_provider.ConsumeIntegral<uint32_t>();

        // If the mempool is non-empty, choose a mempool outpoint. Otherwise, choose a coinbase.
        COutPoint outpoint;
        unsigned long mempool_size = setup->m_node.mempool->size();
        if (fuzzed_data_provider.ConsumeBool() && mempool_size != 0) {
            size_t random_idx = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, mempool_size - 1);
            LOCK(setup->m_node.mempool->cs);
            outpoint = COutPoint(setup->m_node.mempool->txns_randomized[random_idx].second->GetSharedTx()->GetHash(), 0);
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
            prev = setup->m_node.chainman->ActiveChain().Tip()->GetBlockHash();
            height = setup->m_node.chainman->ActiveChain().Height() + 1;
        } else {
            size_t index = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, info.size() - 1);
            prev = info[index].hash;
            height = info[index].height + 1;
        }

        const auto new_time = WITH_LOCK(::cs_main, return setup->m_node.chainman->ActiveChain().Tip()->GetMedianTimePast() + 1);

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

        const auto mempool_size = setup->m_node.mempool->size();
        if (fuzzed_data_provider.ConsumeBool() && mempool_size != 0) {
            // Add txns from the mempool. Since we do not include parents, it may be an invalid block.
            size_t num_txns = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, mempool_size);
            size_t random_idx = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, mempool_size - 1);

            LOCK(setup->m_node.mempool->cs);
            for (size_t i = random_idx; i < random_idx + num_txns; ++i) {
                CTransactionRef mempool_tx = setup->m_node.mempool->txns_randomized[i % mempool_size].second->GetSharedTx();
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

        CBlockIndex* pindexPrev{WITH_LOCK(::cs_main, return setup->m_node.chainman->m_blockman.LookupBlockIndex(prev))};
        setup->m_node.chainman->GenerateCoinbaseCommitment(*block, pindexPrev);

        bool mutated;
        block->hashMerkleRoot = BlockMerkleRoot(*block, &mutated);
        FinalizeHeader(*block, *setup->m_node.chainman);

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
                std::vector<CBlock> headers;
                headers.emplace_back(info[index].block->GetBlockHeader());

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
                    const uint64_t tip_time = WITH_LOCK(::cs_main, return setup->m_node.chainman->ActiveChain().Tip()->GetBlockTime());
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
    setup->m_node.connman->StopNodes();
    setup->m_node.validation_signals->UnregisterAllValidationInterfaces();

    if (WITH_LOCK(g_chainman.GetMutex(), return g_chainman.BlockIndex().size()) != 201 ||
        g_setup->m_node.mempool->size() != 0) {

        MakeRandDeterministicDANGEROUS(uint256::ZERO);
        ResetChainman(*g_setup);
    }
}
