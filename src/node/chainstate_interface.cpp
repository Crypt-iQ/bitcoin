// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/chainstate_interface.h>

#include <chain.h>
#include <node/blockstorage.h>
#include <policy/feerate.h>
#include <txmempool.h>
#include <validation.h>

#include <memory>
#include <utility>

namespace node {

namespace {

/**
 * Production adapter that satisfies IChainAccess by delegating every call
 * to a real ChainstateManager. The adapter holds a non-owning reference to
 * the ChainstateManager - lifetime is managed by the surrounding NodeContext
 * exactly as it always was.
 */
class ChainstateManagerAdapter final : public IChainAccess
{
public:
    explicit ChainstateManagerAdapter(ChainstateManager& chainman) : m_chainman{chainman} {}

    const CChainParams& GetParams() const override { return m_chainman.GetParams(); }
    const Consensus::Params& GetConsensus() const override { return m_chainman.GetConsensus(); }
    VersionBitsCache& VersionBits() const override { return m_chainman.m_versionbitscache; }
    RecursiveMutex& GetMutex() const override LOCK_RETURNED(::cs_main) { return m_chainman.GetMutex(); }

    CChain& ActiveChain() const override EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        return m_chainman.ActiveChain();
    }
    CBlockIndex* ActiveTip() const override EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        return m_chainman.ActiveTip();
    }
    int ActiveHeight() const override EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        return m_chainman.ActiveHeight();
    }

    bool IsInitialBlockDownload() const noexcept override
    {
        return m_chainman.IsInitialBlockDownload();
    }
    const arith_uint256& MinimumChainWork() const override
    {
        return m_chainman.MinimumChainWork();
    }

    CBlockIndex* BestHeader() const override EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        AssertLockHeld(::cs_main);
        return m_chainman.m_best_header;
    }
    void SetBestHeader(CBlockIndex* index) override EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        AssertLockHeld(::cs_main);
        m_chainman.m_best_header = index;
    }

    CBlockIndex* LookupBlockIndex(const uint256& hash) override EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        return m_chainman.m_blockman.LookupBlockIndex(hash);
    }
    const CBlockIndex* LookupBlockIndex(const uint256& hash) const override EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        return m_chainman.m_blockman.LookupBlockIndex(hash);
    }
    bool LoadingBlocks() const override
    {
        return m_chainman.m_blockman.LoadingBlocks();
    }
    bool IsPruneMode() const override
    {
        return m_chainman.m_blockman.IsPruneMode();
    }
    bool IsBlockPruned(const CBlockIndex& block) const override EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        return m_chainman.m_blockman.IsBlockPruned(block);
    }
    bool ReadBlock(CBlock& block, const FlatFilePos& pos, const std::optional<uint256>& expected_hash) const override
    {
        return m_chainman.m_blockman.ReadBlock(block, pos, expected_hash);
    }
    bool ReadBlock(CBlock& block, const CBlockIndex& index) const override
    {
        return m_chainman.m_blockman.ReadBlock(block, index);
    }
    RawBlockResult ReadRawBlock(const FlatFilePos& pos, std::optional<std::pair<size_t, size_t>> block_part) const override
    {
        return m_chainman.m_blockman.ReadRawBlock(pos, block_part);
    }

    const CBlockIndex* FindForkInGlobalIndex(const CBlockLocator& locator) const override EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        return m_chainman.ActiveChainstate().FindForkInGlobalIndex(locator);
    }
    bool ActivateBestChain(BlockValidationState& state, std::shared_ptr<const CBlock> pblock) override
    {
        return m_chainman.ActiveChainstate().ActivateBestChain(state, std::move(pblock));
    }

    const CBlockIndex* CurrentSnapshotBase() const override EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        return m_chainman.CurrentChainstate().SnapshotBase();
    }
    Assumeutxo CurrentAssumeutxoState() const override EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        return m_chainman.CurrentChainstate().m_assumeutxo;
    }

    bool ProcessNewBlock(const std::shared_ptr<const CBlock>& block, bool force_processing, bool min_pow_checked, bool* new_block) override
    {
        return m_chainman.ProcessNewBlock(block, force_processing, min_pow_checked, new_block);
    }
    bool ProcessNewBlockHeaders(std::span<const CBlockHeader> headers, bool min_pow_checked, BlockValidationState& state, const CBlockIndex** ppindex) override
    {
        return m_chainman.ProcessNewBlockHeaders(headers, min_pow_checked, state, ppindex);
    }
    MempoolAcceptResult ProcessTransaction(const CTransactionRef& tx, bool test_accept) override EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        return m_chainman.ProcessTransaction(tx, test_accept);
    }
    PackageMempoolAcceptResult ProcessNewPackage(CTxMemPool& pool, const Package& txns, bool test_accept, const std::optional<CFeeRate>& client_maxfeerate) override
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        return ::ProcessNewPackage(m_chainman.ActiveChainstate(), pool, txns, test_accept, client_maxfeerate);
    }

    void ReportHeadersPresync(int64_t height, int64_t timestamp) override
    {
        m_chainman.ReportHeadersPresync(height, timestamp);
    }
    std::optional<std::pair<const CBlockIndex*, const CBlockIndex*>>
    GetHistoricalBlockRange() const override EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        return m_chainman.GetHistoricalBlockRange();
    }

private:
    ChainstateManager& m_chainman;
};

} // namespace

std::unique_ptr<IChainAccess> MakeChainstateManagerAccess(ChainstateManager& chainman)
{
    return std::make_unique<ChainstateManagerAdapter>(chainman);
}

} // namespace node
