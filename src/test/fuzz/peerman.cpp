// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addrman.h>
#include <banman.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/consensus.h>
#include <consensus/params.h>
#include <crypto/common.h>
#include <net.h>
#include <net_processing.h>
#include <netgroup.h>
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
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace {

/** Fill `block` with a minimal valid coinbase so its `vtx` is non-empty.
 *  PeerManager forwards blocks into helpers (e.g. CBlockHeaderAndShortTxIDs)
 *  that assume `vtx.size() >= 1` and read `vtx[0]`; a real block always has
 *  at least the coinbase tx, so the mock must too whenever it claims a
 *  successful block read. */
void StuffMockBlockWithCoinbase(CBlock& block)
{
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript() << OP_0;
    coinbase.vout.resize(1);
    coinbase.vout[0].nValue = 0;
    coinbase.vout[0].scriptPubKey = CScript();
    block.vtx.clear();
    block.vtx.push_back(MakeTransactionRef(std::move(coinbase)));
}

/**
 * A mock IChainAccess whose return values are entirely driven by flag fields.
 *
 * The fuzzer flips each flag from the input blob and exercises PeerManagerImpl's
 * reaction to every (representable) combination of chain-state replies, without
 * needing a real ChainstateManager / mempool acceptance pipeline.
 *
 * The mock owns a synthetic CBlockIndex and a CChain held by unique_ptr so the
 * chain can be fully reset (including back to empty) between messages. PeerManager
 * only reads basic fields off the block index (nHeight, nChainWork, nTime, hash)
 * so a single synthetic index is sufficient.
 */
class MockChainAccess final : public node::IChainAccess
{
public:
    // ---- Flag knobs the fuzzer can flip ----------------------------------
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
    /** Synthetic chain-work value for the best-header index. When greater than
     *  `flag_tip_chainwork`, this models the (very common) "we have a header
     *  with more work than our active tip but the block isn't connected yet"
     *  state that PeerManager has to reason about throughout block download. */
    uint32_t flag_best_header_chainwork{0x200};
    /** Synthetic height for the best-header index. Independent of the active
     *  tip height; PeerManager uses this to detect that better headers exist
     *  even when blocks haven't been connected. */
    int32_t flag_best_header_height{2};
    int64_t flag_best_header_time{1610000000};

    MempoolAcceptResult::ResultType flag_process_tx_result{MempoolAcceptResult::ResultType::VALID};
    /** When `flag_process_tx_result` is INVALID, this controls which
     *  TxValidationResult code the rejection carries. Different codes drive
     *  different PeerManager branches (orphan handling, peer scoring,
     *  rejection caches, package reconsideration, …). */
    TxValidationResult flag_tx_reject_reason{TxValidationResult::TX_MEMPOOL_POLICY};

    /** Maximum synthetic chain height. Large enough to exceed
     *  MIN_BLOCKS_TO_KEEP (288) and the various ~1000-block horizons that
     *  PeerManager applies to header sync, stale-tip eviction, and
     *  historical-block range checks. */
    static constexpr int kMaxSyntheticHeight = 1050;

    explicit MockChainAccess(const CChainParams& params)
        : m_params(params), m_consensus(params.GetConsensus())
    {
        // Allocate the CBlockIndex / hash storage ONCE and never reallocate.
        // PeerManager captures raw CBlockIndex* into its per-peer CNodeState
        // (e.g. m_chain_sync.m_work_header, pindexBestKnownBlock) on one
        // SendMessages call and dereferences them on a later one. If the
        // mock destroyed and recreated CBlockIndex instances between
        // messages, those captured pointers would dangle (use-after-free).
        // By keeping the underlying storage stable for the lifetime of the
        // MockChainAccess instance, captured pointers stay valid even when
        // flags change. Refreshes only update fields in place.
        const int N = kMaxSyntheticHeight + 1;
        m_hash_storage.resize(N);
        m_status_overlay.assign(N, 0);
        m_index_storage.reserve(N);
        for (int h = 0; h < N; ++h) {
            // Give each height a distinct, deterministic hash so
            // LookupBlockIndex-style identity comparisons behave sensibly.
            WriteLE32(m_hash_storage[h].begin(), static_cast<uint32_t>(h) + 1);
            auto idx = std::make_unique<CBlockIndex>();
            idx->phashBlock = &m_hash_storage[h];
            idx->nHeight = h;
            idx->pprev = (h == 0) ? nullptr : m_index_storage.back().get();
            m_index_storage.push_back(std::move(idx));
        }
        // Wire up pskip after all pprev links are in place.
        for (auto& idx : m_index_storage) idx->BuildSkip();

        m_active_chain = std::make_unique<CChain>();
        RefreshSyntheticIndex();
    }

    /** Update the synthetic chain's per-block metadata in place from the
     *  current flag values. Does NOT reallocate CBlockIndex instances;
     *  pointers handed out previously remain valid.
     *
     *  Topology (re-applied each call):
     *    - Heights [0, active_height] are "full" blocks (BLOCK_HAVE_DATA, nTx=1).
     *    - Heights (active_height, best_header_height] are header-only
     *      (BLOCK_VALID_TREE, nTx=0), modelling "headers ahead of blocks".
     *    - Cumulative chainwork increments by flag_tip_chainwork per active
     *      block, then by flag_best_header_chainwork per extension block.
     *
     *  Takes cs_main internally since CBlockIndex::nStatus is GUARDED_BY(cs_main). */
    void RefreshSyntheticIndex() LOCKS_EXCLUDED(::cs_main)
    {
        LOCK(::cs_main);

        m_active_chain = std::make_unique<CChain>();
        m_minimum_chain_work = arith_uint256{flag_min_chainwork};

        const int active_height = std::clamp(flag_active_height, 0, kMaxSyntheticHeight);
        const int best_header_height = std::clamp(std::max(flag_best_header_height, active_height),
                                                  0, kMaxSyntheticHeight);

        // Update fields in place on the already-allocated indices.
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
            // OR in the fuzzer-controlled overlay. The overlay is already
            // restricted (see RandomizeStatusOverlay) to a "safe" mask that
            // keeps the resulting flags internally consistent:
            //   - HAVE_UNDO only when HAVE_DATA is already set (active section).
            //   - FAILED_VALID and FAILED_CHILD are allowed everywhere; the
            //     validity-state low bits stay clamped to the base value
            //     (TREE for header-only, TREE for active too) so we never
            //     claim a higher validity tier than we've actually backed.
            //   - OPT_WITNESS is informational and always safe.
            uint8_t overlay = m_status_overlay[h];
            // Mask off HAVE_UNDO unless HAVE_DATA is in the base.
            if (!(base & BLOCK_HAVE_DATA)) overlay &= ~uint8_t{BLOCK_HAVE_UNDO};
            // Strip the validity-state low bits from the overlay so they
            // can't bump us above the base.
            overlay &= ~uint8_t{BLOCK_VALID_MASK};
            idx.nStatus = base | overlay;
        }
        // Heights past best_header_height retain whatever fields they had
        // from a previous refresh. They are not reachable via ActiveTip() or
        // BestHeader(), and LookupBlockIndex only ever returns the active
        // tip or best-header pointer, so PeerManager will not observe them.

        CBlockIndex* const active_tip = m_index_storage[active_height].get();
        m_active_chain->SetTip(*active_tip);
        m_active_tip_ptr = active_tip;
        // m_best_header is *always* non-null. It points at the top of the
        // best-header chain, which may be the same as the active tip (when
        // best_header_height == active_height) or a header-only extension
        // beyond the active tip.
        m_best_header_ptr = m_index_storage[best_header_height].get();
    }

    /** Reset every flag to its construction default and rebuild state. */
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
        std::fill(m_status_overlay.begin(), m_status_overlay.end(), uint8_t{0});
        RefreshSyntheticIndex();
    }

    /** Reroll every height's nStatus overlay byte from the fuzz blob.
     *  Each byte is masked to bits PeerManager actually inspects without
     *  creating impossible combinations:
     *      BLOCK_HAVE_UNDO    (16)
     *      BLOCK_FAILED_VALID (32)
     *      BLOCK_FAILED_CHILD (64)
     *      BLOCK_OPT_WITNESS  (128)
     *  The internally-consistent enforcement (HAVE_UNDO requires
     *  HAVE_DATA, validity tier not exceeded) is done in
     *  RefreshSyntheticIndex when these bits are applied. */
    void RandomizeStatusOverlay(FuzzedDataProvider& fdp)
    {
        constexpr uint8_t kSafeMask = static_cast<uint8_t>(
            BLOCK_HAVE_UNDO | BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD | BLOCK_OPT_WITNESS);
        for (auto& byte : m_status_overlay) {
            byte = fdp.ConsumeIntegral<uint8_t>() & kSafeMask;
        }
        RefreshSyntheticIndex();
    }

    /** Consume from the fuzz blob, mutate one flag, then rebuild. Called
     *  between messages so consecutive ProcessMessages calls observe
     *  different chain-state replies. */
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
        case 21: RandomizeStatusOverlay(fdp); return; // Already calls Refresh.
        case 22: /* no-op: occasionally skip mutation */ break;
        }
        RefreshSyntheticIndex();
    }

    // ---- IChainAccess implementation -------------------------------------

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
            return MempoolAcceptResult::Success(/*replaced_transactions=*/{}, /*vsize=*/100, /*fee=*/1000,
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
    // Owning storage. Allocated ONCE in the constructor and never freed
    // until this MockChainAccess goes out of scope at the end of the fuzz
    // iteration. Within an iteration, PeerManager captures raw CBlockIndex*
    // pointers into its per-peer state (pindexBestKnownBlock, m_work_header,
    // …) on one SendMessages call and dereferences them on a later one, so
    // these pointers must outlive every mid-iteration RefreshSyntheticIndex.
    // `m_index_storage[i]->nHeight == i`.
    std::vector<std::unique_ptr<CBlockIndex>> m_index_storage;
    std::vector<uint256> m_hash_storage;
    /** Per-height fuzzer-controlled nStatus overlay. ORed into the
     *  base nStatus each refresh, masked to a "safe" set that keeps the
     *  CBlockIndex internally consistent (no impossible combinations like
     *  HAVE_UNDO without HAVE_DATA, no validity bits past the base state). */
    std::vector<uint8_t> m_status_overlay;
    std::unique_ptr<CChain> m_active_chain;
    CBlockIndex* m_active_tip_ptr{nullptr};
    CBlockIndex* m_best_header_ptr{nullptr};
    arith_uint256 m_minimum_chain_work;
};

} // namespace

void initialize_peerman()
{
    // BasicTestingSetup runs the one-time global initialization that the
    // rest of the codebase assumes is in place (logging, SHA self-test,
    // ECC context, signal handlers, etc.). It does NOT create a
    // ChainstateManager - that's the whole point of this target. The
    // returned setup is held in a function-static so it lives for the
    // entire fuzzing run.
    static const auto testing_setup{
        MakeNoLogFileContext<const BasicTestingSetup>(ChainType::REGTEST)};
    (void)testing_setup;
}

FUZZ_TARGET(peerman, .init = initialize_peerman)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    NodeClockContext clock_ctx{1610000000s};

    // Fresh mock chain each iteration so prior fuzz inputs cannot bleed
    // into the next one through stashed flags or pointers.
    MockChainAccess mock_chain{Params()};
    mock_chain.ResetAllFlags();

    // Seed the initial flag state from the fuzz blob, then rebuild the
    // synthetic chain to reflect it.
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
        // Seed the per-height nStatus overlay from the fuzz blob so the
        // entire block tree starts with random (but valid) flag combinations.
        mock_chain.RandomizeStatusOverlay(fuzzed_data_provider);
    } else {
        mock_chain.RefreshSyntheticIndex();
    }

    // Build the surrounding networking objects locally (no shared TestingSetup
    // chainman). The point of this target is that no real ChainstateManager
    // is needed: the mock above is the only chain-state surface PeerManager
    // sees.
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

    // Build a ValidationSignals dispatcher with an immediate (synchronous)
    // task runner. PeerManager's BlockChecked / NewPoWValidBlock overrides
    // are `protected`, so callers go through ValidationSignals (a friend of
    // CValidationInterface). With ImmediateTaskRunner the dispatch happens
    // inline, so callbacks fire before signals.X(...) returns.
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

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 30)
    {
        // Between every message, optionally mutate one flag on the mock so
        // that consecutive ProcessMessages calls observe different chain-state
        // replies. This is the whole point of the target: prove that varying
        // IChainAccess return values changes the PeerManager code path.
        if (fuzzed_data_provider.ConsumeBool()) {
            mock_chain.MutateFromFuzz(fuzzed_data_provider);
        }

        // Pick a valid wire-protocol message type so we exercise the
        // ProcessMessage dispatcher's known branches, not the unknown-type
        // bail-out. The payload is still fuzzer-controlled; ProcessMessage's
        // per-type deserializer will reject malformed bytes naturally.
        const std::string random_message_type{PickValue(fuzzed_data_provider, ALL_NET_MESSAGE_TYPES)};

        clock_ctx.set(ConsumeTime(fuzzed_data_provider));

        // Optionally fire one of the validation-interface callbacks that
        // PeerManager implements (NewPoWValidBlock, BlockChecked). In a
        // real node these are dispatched by ValidationSignals after
        // ProcessNewBlock; here we call them directly on the PeerManager
        // instance, since they are public virtuals on CValidationInterface.
        // This exercises PeerManager state that's only reachable through
        // those entry points (compact-block announcement bookkeeping in
        // NewPoWValidBlock; block-checked peer scoring & invalid-block
        // tracking in BlockChecked).
        const int cb_choice = fuzzed_data_provider.ConsumeIntegralInRange<int>(0, 3);
        if (cb_choice == 0 || cb_choice == 1) {
            auto pblock = std::make_shared<CBlock>();
            // NewPoWValidBlock dereferences vtx[0] and reads vtx.size() - 1
            // (inside CBlockHeaderAndShortTxIDs), so the block must carry
            // at least a coinbase. BlockChecked doesn't care about vtx but
            // sharing the same shape costs nothing.
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
        // cb_choice == 2 or 3: skip callbacks this iteration.

        CSerializedNetMsg net_msg;
        net_msg.m_type = random_message_type;
        net_msg.data = ConsumeRandomLengthByteVector(fuzzed_data_provider, MAX_PROTOCOL_MESSAGE_LENGTH);

        CNode& random_node = *PickValue(fuzzed_data_provider, peers);

        connman.FlushSendBuffer(random_node);
        (void)connman.ReceiveMsgFrom(random_node, std::move(net_msg));

        bool more_work{true};
        while (more_work) { // Ensure that every message is eventually processed in some way or another
            random_node.fPauseSend = false;

            try {
                more_work = connman.ProcessMessagesOnce(random_node);
            } catch (const std::ios_base::failure&) {
            }
            peerman->SendMessages(random_node);
        }
    }
    // Drain any pending validation callbacks, then unregister PeerManager
    // before either it or `signals` goes out of scope.
    signals.SyncWithValidationInterfaceQueue();
    signals.UnregisterValidationInterface(peerman.get());
    connman.StopNodes();
}
