// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_CHAINSTATE_INTERFACE_H
#define BITCOIN_NODE_CHAINSTATE_INTERFACE_H

#include <arith_uint256.h>
#include <chain.h>
#include <kernel/cs_main.h>
#include <kernel/mempool_entry.h>
#include <node/blockstorage.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <sync.h>
#include <threadsafety.h>
#include <uint256.h>
#include <validation.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <utility>

class CBlockIndex;
struct CBlockLocator;
class CChainParams;
class CFeeRate;
class CTxMemPool;
class VersionBitsCache;
class BlockValidationState;
struct FlatFilePos;
class CBlock;

namespace Consensus { struct Params; }

namespace node {

/**
 * Abstract interface that exposes every ChainstateManager / Chainstate /
 * BlockManager operation that net_processing currently needs.
 *
 * The goal is to break the direct dependency from net_processing on the
 * concrete ChainstateManager so that PeerManagerImpl can be exercised
 * (in fuzz tests, unit tests, or as a future library boundary) against
 * a mock implementation without having to construct a full validation
 * stack.
 *
 * Locking conventions follow the underlying ChainstateManager API: methods
 * that touch the block index, the active chain, or `m_best_header` require
 * `cs_main` to be held. The annotations mirror what net_processing already
 * expects today; the adapter implementation simply forwards.
 *
 * Notes on shape:
 *  - We expose `CBlockIndex*` and `CChain&` directly. These are kernel data
 *    types (not part of validation's internal state machine) and net_processing
 *    already operates on them. The interface intentionally does *not* try to
 *    hide them; it only hides the ChainstateManager/Chainstate plumbing.
 *  - Mempool-acceptance helpers (single-tx and package) live here too because
 *    `ProcessNewPackage` is a free function in validation.h that takes a
 *    `Chainstate&`; net_processing should not have to obtain a real
 *    `Chainstate&` to call it.
 */
class IChainAccess {
public:
    virtual ~IChainAccess() = default;

    // ---- Parameters & misc ------------------------------------------------

    virtual const CChainParams& GetParams() const = 0;
    virtual const Consensus::Params& GetConsensus() const = 0;
    virtual VersionBitsCache& VersionBits() const = 0;
    virtual RecursiveMutex& GetMutex() const LOCK_RETURNED(::cs_main) = 0;

    // ---- Active chain / tip accessors ------------------------------------
    //
    // These mirror ChainstateManager's "active chain" accessors and the
    // `Chainstate::m_chain` view. Net_processing only reads through them.

    virtual CChain& ActiveChain() const EXCLUSIVE_LOCKS_REQUIRED(::cs_main) = 0;
    virtual CBlockIndex* ActiveTip() const EXCLUSIVE_LOCKS_REQUIRED(::cs_main) = 0;
    virtual int ActiveHeight() const EXCLUSIVE_LOCKS_REQUIRED(::cs_main) = 0;

    // ---- IBD / chain-work / state flags ----------------------------------

    virtual bool IsInitialBlockDownload() const noexcept = 0;
    virtual const arith_uint256& MinimumChainWork() const = 0;

    // ---- Best-header tracking --------------------------------------------
    //
    // `m_best_header` is read all over net_processing and is *written* in
    // exactly one place (the initial-sync bootstrap in SendMessages). We
    // expose both a getter and a setter so the field stays encapsulated.

    virtual CBlockIndex* BestHeader() const EXCLUSIVE_LOCKS_REQUIRED(::cs_main) = 0;
    virtual void SetBestHeader(CBlockIndex* index) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) = 0;

    // ---- Block-manager accessors (formerly m_chainman.m_blockman.*) ------

    virtual CBlockIndex* LookupBlockIndex(const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) = 0;
    virtual const CBlockIndex* LookupBlockIndex(const uint256& hash) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main) = 0;
    virtual bool LoadingBlocks() const = 0;
    virtual bool IsPruneMode() const = 0;
    virtual bool IsBlockPruned(const CBlockIndex& block) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main) = 0;
    virtual bool ReadBlock(CBlock& block, const FlatFilePos& pos, const std::optional<uint256>& expected_hash) const = 0;
    virtual bool ReadBlock(CBlock& block, const CBlockIndex& index) const = 0;

    using RawBlockResult = util::Expected<std::vector<std::byte>, ReadRawError>;
    virtual RawBlockResult ReadRawBlock(const FlatFilePos& pos, std::optional<std::pair<size_t, size_t>> block_part = std::nullopt) const = 0;

    // ---- Active-chainstate operations ------------------------------------
    //
    // FindForkInGlobalIndex and ActivateBestChain live on `Chainstate`, not
    // on `ChainstateManager`. From net_processing's perspective they are
    // logically "the active chainstate's …", so we expose them here.

    virtual const CBlockIndex* FindForkInGlobalIndex(const CBlockLocator& locator) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main) = 0;
    virtual bool ActivateBestChain(BlockValidationState& state, std::shared_ptr<const CBlock> pblock) = 0;

    // ---- Snapshot / assumeutxo metadata ----------------------------------

    virtual const CBlockIndex* CurrentSnapshotBase() const EXCLUSIVE_LOCKS_REQUIRED(::cs_main) = 0;
    virtual Assumeutxo CurrentAssumeutxoState() const EXCLUSIVE_LOCKS_REQUIRED(::cs_main) = 0;

    // ---- Block / header / transaction processing -------------------------

    virtual bool ProcessNewBlock(const std::shared_ptr<const CBlock>& block,
                                 bool force_processing,
                                 bool min_pow_checked,
                                 bool* new_block) = 0;

    virtual bool ProcessNewBlockHeaders(std::span<const CBlockHeader> headers,
                                        bool min_pow_checked,
                                        BlockValidationState& state,
                                        const CBlockIndex** ppindex = nullptr) = 0;

    virtual MempoolAcceptResult ProcessTransaction(const CTransactionRef& tx, bool test_accept = false)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main) = 0;

    /** Process a transaction package on the active chainstate. Wraps the
     *  free function `::ProcessNewPackage(active_chainstate, …)` so callers
     *  do not need a `Chainstate&`. */
    virtual PackageMempoolAcceptResult ProcessNewPackage(CTxMemPool& pool,
                                                        const Package& txns,
                                                        bool test_accept,
                                                        const std::optional<CFeeRate>& client_maxfeerate)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main) = 0;

    // ---- Misc reporting --------------------------------------------------

    virtual void ReportHeadersPresync(int64_t height, int64_t timestamp) = 0;

    virtual std::optional<std::pair<const CBlockIndex*, const CBlockIndex*>>
        GetHistoricalBlockRange() const EXCLUSIVE_LOCKS_REQUIRED(::cs_main) = 0;
};

/**
 * Production adapter: forwards every call onto a real ChainstateManager.
 * Lives in node/ so it can include validation.h freely; net_processing does
 * not need to include it.
 */
std::unique_ptr<IChainAccess> MakeChainstateManagerAccess(ChainstateManager& chainman);

} // namespace node

#endif // BITCOIN_NODE_CHAINSTATE_INTERFACE_H
