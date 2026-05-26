// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addrman.h>
#include <banman.h>
#include <blockencodings.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/consensus.h>
#include <consensus/params.h>
#include <crypto/common.h>
#include <net.h>
#include <net_processing.h>
#include <netgroup.h>
#include <netmessagemaker.h>
#include <node/chainstate_interface.h>
#include <node/warnings.h>
#include <policy/feerate.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <protocol.h>
#include <script/script.h>
#include <sync.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/fuzz/util/net.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <test/util/time.h>
#include <txmempool.h>
#include <util/check.h>
#include <util/task_runner.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>
#include <versionbits.h>

#include <ios>
#include <list>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace {

struct MockBlockInfo {
    std::shared_ptr<CBlock> block;
    uint256 hash;
    int32_t height;
};

class FuzzedCBlockHeaderAndShortTxIDs : public CBlockHeaderAndShortTxIDs
{
    using CBlockHeaderAndShortTxIDs::CBlockHeaderAndShortTxIDs;

public:
    void AddPrefilledTx(PrefilledTransaction&& prefilledtx)
    {
        prefilledtxn.push_back(std::move(prefilledtx));
    }

    void RemoveCoinbasePrefill()
    {
        prefilledtxn.erase(prefilledtxn.begin());
    }

    void InsertCoinbaseShortTxID(uint64_t shorttxid)
    {
        shorttxids.insert(shorttxids.begin(), shorttxid);
    }

    void EraseShortTxIDs(size_t index)
    {
        shorttxids.erase(shorttxids.begin() + index);
    }

    size_t PrefilledTxCount() { return prefilledtxn.size(); }
    size_t ShortTxIDCount() { return shorttxids.size(); }
};

void StuffMockBlockWithCoinbase(CBlock& block, int32_t height = 0)
{
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript() << height << OP_0;
    coinbase.vout.resize(1);
    coinbase.vout[0].nValue = 0;
    coinbase.vout[0].scriptPubKey = CScript();
    block.vtx.clear();
    block.vtx.push_back(MakeTransactionRef(std::move(coinbase)));
}

CTransactionRef MakeMockTx(FuzzedDataProvider& fdp)
{
    CMutableTransaction tx_mut;
    tx_mut.version = fdp.ConsumeIntegral<int32_t>();
    tx_mut.nLockTime = fdp.ConsumeIntegral<uint32_t>();

    const size_t num_inputs = fdp.ConsumeIntegralInRange<size_t>(1, 3);
    for (size_t i = 0; i < num_inputs; ++i) {
        CTxIn in;
        uint256 prev;
        WriteLE32(prev.begin(), fdp.ConsumeIntegral<uint32_t>());
        in.prevout = COutPoint(Txid::FromUint256(prev), fdp.ConsumeIntegral<uint32_t>());
        in.nSequence = fdp.ConsumeIntegral<uint32_t>();
        in.scriptSig = CScript();
        tx_mut.vin.push_back(in);
    }

    const size_t num_outputs = fdp.ConsumeIntegralInRange<size_t>(1, 3);
    for (size_t i = 0; i < num_outputs; ++i) {
        CTxOut out;
        out.nValue = fdp.ConsumeIntegralInRange<CAmount>(0, 100000);
        out.scriptPubKey = CScript();
        tx_mut.vout.push_back(out);
    }

    return MakeTransactionRef(std::move(tx_mut));
}

class MockChainAccess final : public node::IChainAccess
{
public:
    bool flag_ibd{false};
    bool flag_loading_blocks{false};
    bool flag_prune_mode{false};
    bool flag_block_pruned{false};
    bool flag_lookup_returns_index{true};
    bool flag_process_new_block{true};
    bool flag_process_new_block_headers{true};
    bool flag_activate_best_chain{true};
    bool flag_read_block{true};
    bool flag_read_raw_block{true};
    bool flag_have_historical_range{false};
    Assumeutxo flag_assumeutxo_state{Assumeutxo::VALIDATED};

    int32_t flag_active_height{1};
    int64_t flag_active_tip_time{1610000000};
    uint32_t flag_tip_chainwork{0x100};
    uint32_t flag_min_chainwork{0x10};
    uint32_t flag_best_header_chainwork{0x200};
    int32_t flag_best_header_height{2};
    int64_t flag_best_header_time{1610000000};

    MempoolAcceptResult::ResultType flag_process_tx_result{MempoolAcceptResult::ResultType::VALID};
    TxValidationResult flag_tx_reject_reason{TxValidationResult::TX_MEMPOOL_POLICY};

    std::list<CTransactionRef> flag_replaced_transactions;

    static constexpr int kMaxSyntheticHeight = 1050;

    explicit MockChainAccess(const CChainParams& params)
        : m_params(params), m_consensus(params.GetConsensus())
    {
        const int N = kMaxSyntheticHeight + 1;
        m_hash_storage.resize(N);
        m_status_overlay.assign(N, 0);
        m_index_storage.reserve(N);
        for (int h = 0; h < N; ++h) {
            WriteLE32(m_hash_storage[h].begin(), static_cast<uint32_t>(h) + 1);
            auto idx = std::make_unique<CBlockIndex>();
            idx->phashBlock = &m_hash_storage[h];
            idx->nHeight = h;
            idx->pprev = (h == 0) ? nullptr : m_index_storage.back().get();
            m_index_storage.push_back(std::move(idx));
        }
        for (auto& idx : m_index_storage) idx->BuildSkip();

        m_active_chain = std::make_unique<CChain>();
        RefreshSyntheticIndex();
    }

    void RefreshSyntheticIndex() LOCKS_EXCLUDED(::cs_main)
    {
        LOCK(::cs_main);

        m_active_chain = std::make_unique<CChain>();
        m_minimum_chain_work = arith_uint256{flag_min_chainwork};

        const int active_height = std::clamp(flag_active_height, 0, kMaxSyntheticHeight);
        const int best_header_height = std::clamp(std::max(flag_best_header_height, active_height),
                                                  0, kMaxSyntheticHeight);

        arith_uint256 cum_work{0};
        for (int h = 0; h <= best_header_height; ++h) {
            CBlockIndex& idx = *m_index_storage[h];
            idx.nTime = static_cast<uint32_t>(flag_active_tip_time) + static_cast<uint32_t>(h);
            const uint32_t contrib = (h <= active_height) ? flag_tip_chainwork
                                                          : flag_best_header_chainwork;
            cum_work += arith_uint256{contrib};
            idx.nChainWork = cum_work;
            uint32_t base;
            if (h <= active_height) {
                base = BLOCK_VALID_TREE | BLOCK_HAVE_DATA;
                idx.nTx = 1;
            } else {
                base = BLOCK_VALID_TREE;
                idx.nTx = 0;
            }
            uint8_t overlay = m_status_overlay[h];
            if (!(base & BLOCK_HAVE_DATA)) overlay &= ~uint8_t{BLOCK_HAVE_UNDO};
            overlay &= ~uint8_t{BLOCK_VALID_MASK};
            idx.nStatus = base | overlay;
        }

        CBlockIndex* const active_tip = m_index_storage[active_height].get();
        m_active_chain->SetTip(*active_tip);
        m_active_tip_ptr = active_tip;
        m_best_header_ptr = m_index_storage[best_header_height].get();
    }

    void ResetAllFlags()
    {
        flag_ibd = false;
        flag_loading_blocks = false;
        flag_prune_mode = false;
        flag_block_pruned = false;
        flag_lookup_returns_index = true;
        flag_process_new_block = true;
        flag_process_new_block_headers = true;
        flag_activate_best_chain = true;
        flag_read_block = true;
        flag_read_raw_block = true;
        flag_have_historical_range = false;
        flag_assumeutxo_state = Assumeutxo::VALIDATED;
        flag_active_height = 1;
        flag_active_tip_time = 1610000000;
        flag_tip_chainwork = 0x100;
        flag_min_chainwork = 0x10;
        flag_best_header_chainwork = 0x200;
        flag_best_header_height = 2;
        flag_best_header_time = 1610000000;
        flag_process_tx_result = MempoolAcceptResult::ResultType::VALID;
        flag_tx_reject_reason = TxValidationResult::TX_MEMPOOL_POLICY;
        flag_replaced_transactions.clear();
        std::fill(m_status_overlay.begin(), m_status_overlay.end(), uint8_t{0});
        RefreshSyntheticIndex();
    }

    void RandomizeStatusOverlay(FuzzedDataProvider& fdp)
    {
        constexpr uint8_t kSafeMask = static_cast<uint8_t>(
            BLOCK_HAVE_UNDO | BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD | BLOCK_OPT_WITNESS);
        for (auto& byte : m_status_overlay) {
            byte = fdp.ConsumeIntegral<uint8_t>() & kSafeMask;
        }
        RefreshSyntheticIndex();
    }

    void MutateFromFuzz(FuzzedDataProvider& fdp)
    {
        const auto selector = fdp.ConsumeIntegralInRange<int>(0, 22);
        switch (selector) {
        case  0: flag_ibd                       = fdp.ConsumeBool(); break;
        case  1: flag_loading_blocks            = fdp.ConsumeBool(); break;
        case  2: flag_prune_mode                = fdp.ConsumeBool(); break;
        case  3: flag_block_pruned              = fdp.ConsumeBool(); break;
        case  4: flag_lookup_returns_index      = fdp.ConsumeBool(); break;
        case  5: flag_process_new_block         = fdp.ConsumeBool(); break;
        case  6: flag_process_new_block_headers = fdp.ConsumeBool(); break;
        case  7: flag_activate_best_chain       = fdp.ConsumeBool(); break;
        case  8: flag_read_block                = fdp.ConsumeBool(); break;
        case  9: flag_read_raw_block            = fdp.ConsumeBool(); break;
        case 10: flag_have_historical_range     = fdp.ConsumeBool(); break;
        case 11: flag_assumeutxo_state          = fdp.PickValueInArray({Assumeutxo::VALIDATED,
                                                                         Assumeutxo::UNVALIDATED,
                                                                         Assumeutxo::INVALID}); break;
        case 12: flag_active_height             = fdp.ConsumeIntegralInRange<int32_t>(-1, 1'000'000); break;
        case 13: flag_active_tip_time           = fdp.ConsumeIntegral<int64_t>(); break;
        case 14: flag_tip_chainwork             = fdp.ConsumeIntegral<uint32_t>(); break;
        case 15: flag_min_chainwork             = fdp.ConsumeIntegral<uint32_t>(); break;
        case 16: flag_best_header_chainwork     = fdp.ConsumeIntegral<uint32_t>(); break;
        case 17: flag_best_header_height        = fdp.ConsumeIntegralInRange<int32_t>(-1, 1'000'000); break;
        case 18: flag_best_header_time          = fdp.ConsumeIntegral<int64_t>(); break;
        case 19: flag_process_tx_result         = fdp.ConsumeBool()
                     ? MempoolAcceptResult::ResultType::VALID
                     : MempoolAcceptResult::ResultType::INVALID; break;
        case 20: flag_tx_reject_reason          = fdp.PickValueInArray({
                     TxValidationResult::TX_CONSENSUS,
                     TxValidationResult::TX_INPUTS_NOT_STANDARD,
                     TxValidationResult::TX_NOT_STANDARD,
                     TxValidationResult::TX_MISSING_INPUTS,
                     TxValidationResult::TX_PREMATURE_SPEND,
                     TxValidationResult::TX_WITNESS_MUTATED,
                     TxValidationResult::TX_WITNESS_STRIPPED,
                     TxValidationResult::TX_CONFLICT,
                     TxValidationResult::TX_MEMPOOL_POLICY,
                     TxValidationResult::TX_NO_MEMPOOL,
                     TxValidationResult::TX_RECONSIDERABLE,
                     TxValidationResult::TX_UNKNOWN,
                 }); break;
        case 21: RandomizeStatusOverlay(fdp); return;
        case 22: break;
        }
        RefreshSyntheticIndex();
    }

    int32_t ExtendInternalChain(bool also_extend_active)
    {
        const int32_t new_best = std::clamp(flag_best_header_height + 1, 0, kMaxSyntheticHeight);
        if (new_best == flag_best_header_height) return -1;
        flag_best_header_height = new_best;
        if (also_extend_active) {
            flag_active_height = std::clamp(flag_active_height + 1, 0, new_best);
        }
        RefreshSyntheticIndex();
        return new_best;
    }

    uint256 GetSyntheticHashAt(int32_t height) const
    {
        const int32_t h = std::clamp(height, 0, kMaxSyntheticHeight);
        return m_hash_storage[h];
    }

    int32_t GetActiveTipHeightSafe() const
    {
        return std::clamp(flag_active_height, 0, kMaxSyntheticHeight);
    }

    int32_t GetBestHeaderHeightSafe() const
    {
        return std::clamp(std::max(flag_best_header_height, flag_active_height), 0, kMaxSyntheticHeight);
    }

    const CChainParams& GetParams() const override { return m_params; }
    const Consensus::Params& GetConsensus() const override { return m_consensus; }
    VersionBitsCache& VersionBits() const override { return m_versionbits; }
    RecursiveMutex& GetMutex() const override LOCK_RETURNED(::cs_main) { return ::cs_main; }

    CChain& ActiveChain() const override { return *m_active_chain; }
    CBlockIndex* ActiveTip() const override { return m_active_tip_ptr; }
    int ActiveHeight() const override { return m_active_tip_ptr ? m_active_tip_ptr->nHeight : -1; }

    bool IsInitialBlockDownload() const noexcept override { return flag_ibd; }
    const arith_uint256& MinimumChainWork() const override { return m_minimum_chain_work; }

    CBlockIndex* BestHeader() const override { return m_best_header_ptr; }
    void SetBestHeader(CBlockIndex* index) override { m_best_header_ptr = index; }

    CBlockIndex* LookupBlockIndex(const uint256& /*hash*/) override
    {
        return flag_lookup_returns_index ? m_best_header_ptr : nullptr;
    }
    const CBlockIndex* LookupBlockIndex(const uint256& /*hash*/) const override
    {
        return flag_lookup_returns_index ? m_best_header_ptr : nullptr;
    }

    bool LoadingBlocks() const override { return flag_loading_blocks; }
    bool IsPruneMode() const override { return flag_prune_mode; }
    bool IsBlockPruned(const CBlockIndex& /*block*/) const override { return flag_block_pruned; }

    bool ReadBlock(CBlock& block, const FlatFilePos& /*pos*/, const std::optional<uint256>& /*expected_hash*/) const override
    {
        StuffMockBlockWithCoinbase(block);
        return true;
    }
    bool ReadBlock(CBlock& block, const CBlockIndex& /*index*/) const override
    {
        StuffMockBlockWithCoinbase(block);
        return true;
    }
    RawBlockResult ReadRawBlock(const FlatFilePos& /*pos*/, std::optional<std::pair<size_t, size_t>> /*block_part*/) const override
    {
        if (!flag_read_raw_block) return util::Unexpected{node::ReadRawError::IO};
        return std::vector<std::byte>{};
    }

    const CBlockIndex* FindForkInGlobalIndex(const CBlockLocator& /*locator*/) const override
    {
        return flag_lookup_returns_index ? m_best_header_ptr : nullptr;
    }
    bool ActivateBestChain(BlockValidationState& /*state*/, std::shared_ptr<const CBlock> /*pblock*/) override
    {
        return flag_activate_best_chain;
    }

    const CBlockIndex* CurrentSnapshotBase() const override { return nullptr; }
    Assumeutxo CurrentAssumeutxoState() const override { return flag_assumeutxo_state; }

    bool ProcessNewBlock(const std::shared_ptr<const CBlock>& /*block*/, bool /*force_processing*/,
                         bool /*min_pow_checked*/, bool* new_block) override
    {
        if (new_block) *new_block = flag_process_new_block;
        return flag_process_new_block;
    }
    bool ProcessNewBlockHeaders(std::span<const CBlockHeader> /*headers*/, bool /*min_pow_checked*/,
                                BlockValidationState& /*state*/, const CBlockIndex** ppindex) override
    {
        if (ppindex) *ppindex = flag_lookup_returns_index ? m_best_header_ptr : nullptr;
        return flag_process_new_block_headers;
    }
    MempoolAcceptResult ProcessTransaction(const CTransactionRef& /*tx*/, bool /*test_accept*/) override
    {
        if (flag_process_tx_result == MempoolAcceptResult::ResultType::VALID) {
            auto replaced = flag_replaced_transactions;
            return MempoolAcceptResult::Success(std::move(replaced), /*vsize=*/100, /*fee=*/1000,
                                                /*effective_feerate=*/CFeeRate{1000},
                                                /*effective_feerate_wtxids=*/{});
        }
        TxValidationState s;
        s.Invalid(flag_tx_reject_reason, "mock-rejection");
        return MempoolAcceptResult::Failure(s);
    }
    PackageMempoolAcceptResult ProcessNewPackage(CTxMemPool& /*pool*/, const Package& /*txns*/, bool /*test_accept*/,
                                                 const std::optional<CFeeRate>& /*client_maxfeerate*/) override
    {
        return PackageMempoolAcceptResult{{}, {}};
    }

    void ReportHeadersPresync(int64_t /*height*/, int64_t /*timestamp*/) override {}
    std::optional<std::pair<const CBlockIndex*, const CBlockIndex*>> GetHistoricalBlockRange() const override
    {
        if (!flag_have_historical_range || m_index_storage.empty()) return std::nullopt;
        const CBlockIndex* genesis = m_index_storage.front().get();
        const CBlockIndex* tip = m_best_header_ptr;
        return std::make_pair(genesis, tip);
    }

private:
    const CChainParams& m_params;
    const Consensus::Params& m_consensus;
    mutable VersionBitsCache m_versionbits;
    std::vector<std::unique_ptr<CBlockIndex>> m_index_storage;
    std::vector<uint256> m_hash_storage;
    std::vector<uint8_t> m_status_overlay;
    std::unique_ptr<CChain> m_active_chain;
    CBlockIndex* m_active_tip_ptr{nullptr};
    CBlockIndex* m_best_header_ptr{nullptr};
    arith_uint256 m_minimum_chain_work;
};

} // namespace

void initialize_peerman()
{
    static const auto testing_setup{
        MakeNoLogFileContext<const BasicTestingSetup>(ChainType::REGTEST)};
    (void)testing_setup;
}

FUZZ_TARGET(peerman, .init = initialize_peerman)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    NodeClockContext clock_ctx{1610000000s};

    MockChainAccess mock_chain{Params()};
    mock_chain.ResetAllFlags();

    mock_chain.flag_ibd                       = fuzzed_data_provider.ConsumeBool();
    mock_chain.flag_loading_blocks            = fuzzed_data_provider.ConsumeBool();
    mock_chain.flag_prune_mode                = fuzzed_data_provider.ConsumeBool();
    mock_chain.flag_block_pruned              = fuzzed_data_provider.ConsumeBool();
    mock_chain.flag_lookup_returns_index      = fuzzed_data_provider.ConsumeBool();
    mock_chain.flag_process_new_block         = fuzzed_data_provider.ConsumeBool();
    mock_chain.flag_process_new_block_headers = fuzzed_data_provider.ConsumeBool();
    mock_chain.flag_activate_best_chain       = fuzzed_data_provider.ConsumeBool();
    mock_chain.flag_read_block                = fuzzed_data_provider.ConsumeBool();
    mock_chain.flag_read_raw_block            = fuzzed_data_provider.ConsumeBool();
    mock_chain.flag_have_historical_range     = fuzzed_data_provider.ConsumeBool();
    mock_chain.flag_assumeutxo_state          = fuzzed_data_provider.PickValueInArray(
        {Assumeutxo::VALIDATED, Assumeutxo::UNVALIDATED, Assumeutxo::INVALID});
    mock_chain.flag_active_height             = fuzzed_data_provider.ConsumeIntegralInRange<int32_t>(-1, 1'000'000);
    mock_chain.flag_active_tip_time           = fuzzed_data_provider.ConsumeIntegral<int64_t>();
    mock_chain.flag_tip_chainwork             = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
    mock_chain.flag_min_chainwork             = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
    mock_chain.flag_best_header_chainwork     = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
    mock_chain.flag_best_header_height        = fuzzed_data_provider.ConsumeIntegralInRange<int32_t>(-1, 1'000'000);
    mock_chain.flag_best_header_time          = fuzzed_data_provider.ConsumeIntegral<int64_t>();
    mock_chain.flag_process_tx_result         = fuzzed_data_provider.ConsumeBool()
        ? MempoolAcceptResult::ResultType::VALID
        : MempoolAcceptResult::ResultType::INVALID;
    mock_chain.flag_tx_reject_reason          = fuzzed_data_provider.PickValueInArray({
        TxValidationResult::TX_CONSENSUS,
        TxValidationResult::TX_INPUTS_NOT_STANDARD,
        TxValidationResult::TX_NOT_STANDARD,
        TxValidationResult::TX_MISSING_INPUTS,
        TxValidationResult::TX_PREMATURE_SPEND,
        TxValidationResult::TX_WITNESS_MUTATED,
        TxValidationResult::TX_WITNESS_STRIPPED,
        TxValidationResult::TX_CONFLICT,
        TxValidationResult::TX_MEMPOOL_POLICY,
        TxValidationResult::TX_NO_MEMPOOL,
        TxValidationResult::TX_RECONSIDERABLE,
        TxValidationResult::TX_UNKNOWN,
    });
    if (fuzzed_data_provider.ConsumeBool()) {
        mock_chain.RandomizeStatusOverlay(fuzzed_data_provider);
    } else {
        mock_chain.RefreshSyntheticIndex();
    }

    auto netgroupman{NetGroupManager::NoAsmap()};
    AddrMan addrman{netgroupman, /*deterministic=*/true, /*consistency_check_ratio=*/0};
    ConnmanTestMsg connman{0x1337, 0x1337, addrman, netgroupman, Params(),
                           /*network_active=*/true};
    bilingual_str mempool_error;
    CTxMemPool::Options mempool_opts{};
    mempool_opts.check_ratio = 0;
    mempool_opts.signals = nullptr;
    CTxMemPool mempool{std::move(mempool_opts), mempool_error};
    Assert(mempool_error.empty());
    node::Warnings warnings{};

    auto peerman = PeerManager::make(connman, addrman, /*banman=*/nullptr,
                                     static_cast<node::IChainAccess&>(mock_chain),
                                     mempool, warnings,
                                     PeerManager::Options{
                                         .reconcile_txs = true,
                                         .deterministic_rng = true,
                                     });
    connman.SetMsgProc(peerman.get());
    connman.SetAddrman(addrman);

    ValidationSignals signals{std::make_unique<util::ImmediateTaskRunner>()};
    signals.RegisterValidationInterface(peerman.get());

    LOCK(NetEventsInterface::g_msgproc_mutex);

    std::vector<CNode*> peers;
    const auto num_peers_to_add = fuzzed_data_provider.ConsumeIntegralInRange(1, 3);
    for (int i = 0; i < num_peers_to_add; ++i) {
        peers.push_back(ConsumeNodeAsUniquePtr(fuzzed_data_provider, i).release());
        CNode& p2p_node = *peers.back();

        FillNode(fuzzed_data_provider, connman, p2p_node);

        connman.AddTestNode(p2p_node);
    }

    std::vector<MockBlockInfo> mock_blocks;

    auto create_mock_block = [&]() -> MockBlockInfo {
        uint256 prev;
        int32_t height;

        if (mock_blocks.empty() || fuzzed_data_provider.ConsumeBool()) {
            const int32_t tip_height = mock_chain.GetActiveTipHeightSafe();
            prev = mock_chain.GetSyntheticHashAt(tip_height);
            height = tip_height + 1;
        } else {
            const size_t index = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, mock_blocks.size() - 1);
            prev = mock_blocks[index].hash;
            height = mock_blocks[index].height + 1;
        }

        std::shared_ptr<CBlock> block = std::make_shared<CBlock>();
        block->nVersion = fuzzed_data_provider.ConsumeIntegral<int32_t>();
        block->hashPrevBlock = prev;
        block->nTime = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
        block->nBits = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
        block->nNonce = fuzzed_data_provider.ConsumeIntegral<uint32_t>();

        StuffMockBlockWithCoinbase(*block, height);

        const size_t num_extra_txs = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 5);
        for (size_t i = 0; i < num_extra_txs; ++i) {
            block->vtx.push_back(MakeMockTx(fuzzed_data_provider));
        }

        uint256 fake_merkle;
        WriteLE32(fake_merkle.begin(), fuzzed_data_provider.ConsumeIntegral<uint32_t>());
        block->hashMerkleRoot = fake_merkle;

        MockBlockInfo bi;
        bi.block = block;
        bi.hash = block->GetHash();
        bi.height = height;

        if (fuzzed_data_provider.ConsumeBool()) {
            mock_chain.ExtendInternalChain(/*also_extend_active=*/fuzzed_data_provider.ConsumeBool());
        }

        return bi;
    };

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 30)
    {
        if (fuzzed_data_provider.ConsumeBool()) {
            mock_chain.MutateFromFuzz(fuzzed_data_provider);
        }

        clock_ctx.set(ConsumeTime(fuzzed_data_provider));

        const int cb_choice = fuzzed_data_provider.ConsumeIntegralInRange<int>(0, 3);
        if (cb_choice == 0 || cb_choice == 1) {
            auto pblock = std::make_shared<CBlock>();
            StuffMockBlockWithCoinbase(*pblock);

            CBlockIndex* pindex = WITH_LOCK(::cs_main, return cb_choice == 0 ? mock_chain.ActiveTip()
                                                                              : mock_chain.BestHeader());
            if (cb_choice == 0) {
                signals.NewPoWValidBlock(pindex, pblock);
            } else {
                BlockValidationState state;
                if (fuzzed_data_provider.ConsumeBool()) {
                    state.Invalid(fuzzed_data_provider.PickValueInArray({
                        BlockValidationResult::BLOCK_CONSENSUS,
                        BlockValidationResult::BLOCK_CACHED_INVALID,
                        BlockValidationResult::BLOCK_INVALID_HEADER,
                        BlockValidationResult::BLOCK_MUTATED,
                        BlockValidationResult::BLOCK_MISSING_PREV,
                        BlockValidationResult::BLOCK_INVALID_PREV,
                        BlockValidationResult::BLOCK_TIME_FUTURE,
                        BlockValidationResult::BLOCK_HEADER_LOW_WORK,
                    }), "mock-block-reject");
                }
                signals.BlockChecked(pblock, state);
            }
        }

        if (fuzzed_data_provider.ConsumeBool()) {
            const size_t num_replaced = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 3);
            mock_chain.flag_replaced_transactions.clear();
            for (size_t i = 0; i < num_replaced; ++i) {
                mock_chain.flag_replaced_transactions.push_back(MakeMockTx(fuzzed_data_provider));
            }
        }

        CSerializedNetMsg net_msg;
        bool sent_net_msg = true;

        const int action = fuzzed_data_provider.ConsumeIntegralInRange<int>(0, 6);
        switch (action) {
        case 0: {
            std::shared_ptr<CBlock> cblock;
            if (fuzzed_data_provider.ConsumeBool() && !mock_blocks.empty()) {
                size_t index = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, mock_blocks.size() - 1);
                cblock = mock_blocks[index].block;
            } else {
                MockBlockInfo bi = create_mock_block();
                cblock = bi.block;
                mock_blocks.push_back(bi);
            }

            uint64_t nonce = fuzzed_data_provider.ConsumeIntegral<uint64_t>();
            FuzzedCBlockHeaderAndShortTxIDs cmpctblock(*cblock, nonce);

            if (fuzzed_data_provider.ConsumeBool()) {
                CBlockHeaderAndShortTxIDs base_cmpctblock = cmpctblock;
                net_msg = NetMsg::Make(NetMsgType::CMPCTBLOCK, base_cmpctblock);
                break;
            }

            int prev_idx = 0;
            size_t num_erased = 1;
            size_t num_txs = cblock->vtx.size();

            for (size_t i = 0; i < num_txs; ++i) {
                if (i == 0) {
                    if (fuzzed_data_provider.ConsumeBool()) continue;
                    num_erased = 0;
                    uint64_t coinbase_shortid = cmpctblock.GetShortID(cblock->vtx[0]->GetWitnessHash());
                    cmpctblock.RemoveCoinbasePrefill();
                    cmpctblock.InsertCoinbaseShortTxID(coinbase_shortid);
                    continue;
                }

                if (fuzzed_data_provider.ConsumeBool()) continue;

                uint16_t prefill_idx = num_erased == 0 ? i : i - prev_idx - 1;
                prev_idx = i;
                CTransactionRef txref = cblock->vtx[i];
                PrefilledTransaction prefilledtx = {/*index=*/prefill_idx, txref};
                cmpctblock.AddPrefilledTx(std::move(prefilledtx));

                cmpctblock.EraseShortTxIDs(i - num_erased);
                ++num_erased;
            }

            assert(cmpctblock.PrefilledTxCount() + cmpctblock.ShortTxIDCount() == num_txs);

            CBlockHeaderAndShortTxIDs base_cmpctblock = cmpctblock;
            net_msg = NetMsg::Make(NetMsgType::CMPCTBLOCK, base_cmpctblock);
            break;
        }
        case 1: {
            if (mock_blocks.empty()) { sent_net_msg = false; break; }
            size_t index = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, mock_blocks.size() - 1);
            const MockBlockInfo& bi = mock_blocks[index];
            BlockTransactions block_txn;
            block_txn.blockhash = bi.hash;
            std::shared_ptr<CBlock> cblock = bi.block;

            for (size_t i = 0; i < cblock->vtx.size(); i++) {
                if (fuzzed_data_provider.ConsumeBool()) continue;
                block_txn.txn.push_back(cblock->vtx[i]);
            }

            net_msg = NetMsg::Make(NetMsgType::BLOCKTXN, block_txn);
            break;
        }
        case 2: {
            if (mock_blocks.empty()) { sent_net_msg = false; break; }
            size_t index = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, mock_blocks.size() - 1);
            CBlock block = *mock_blocks[index].block;
            block.vtx.clear();
            std::vector<CBlock> headers;
            headers.emplace_back(block);

            net_msg = NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(headers));
            break;
        }
        case 3: {
            bool hb = fuzzed_data_provider.ConsumeBool();
            uint64_t version{fuzzed_data_provider.ConsumeBool() ? CMPCTBLOCKS_VERSION : fuzzed_data_provider.ConsumeIntegral<uint64_t>()};
            net_msg = NetMsg::Make(NetMsgType::SENDCMPCT, /*high_bandwidth=*/hb, /*version=*/version);
            break;
        }
        case 4: {
            MockBlockInfo bi = create_mock_block();
            mock_blocks.push_back(bi);
            sent_net_msg = false;
            break;
        }
        case 5: {
            CTransactionRef tx = MakeMockTx(fuzzed_data_provider);
            net_msg = NetMsg::Make(NetMsgType::TX, TX_WITH_WITNESS(*tx));
            break;
        }
        case 6: {
            const std::string random_message_type{PickValue(fuzzed_data_provider, ALL_NET_MESSAGE_TYPES)};
            net_msg.m_type = random_message_type;
            net_msg.data = ConsumeRandomLengthByteVector(fuzzed_data_provider, MAX_PROTOCOL_MESSAGE_LENGTH);
            break;
        }
        }

        if (!sent_net_msg) continue;

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
            peerman->SendMessages(random_node);
        }
    }
    signals.SyncWithValidationInterfaceQueue();
    signals.UnregisterValidationInterface(peerman.get());
    connman.StopNodes();
}
