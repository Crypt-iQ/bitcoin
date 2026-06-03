#include <addrman.h>
#include <consensus/validation.h>
#include <net_processing.h>
#include <node/warnings.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/fuzz/util/net.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <test/util/time.h>
#include <util/task_runner.h>
#include <validation.h>

#include <optional>

namespace {

using BlockMap = std::unordered_map<uint256, CBlockIndex, BlockHasher>;

class FuzzedNetValidation : public NetValidationInterface
{
public:
    FuzzedNetValidation(FuzzedDataProvider& fdp, const CChainParams& params) : m_fdp(fdp), m_params(params), m_consensus(params.GetConsensus())
    {
        const CBlock& block = m_params.GenesisBlock();
        uint256 hash{block.GetHash()};
        CBlockHeader header{block};
        std::pair<BlockMap::iterator, bool> it = m_blockmap.emplace(hash, header);
        m_best_header = &it.first->second;
        m_best_header->phashBlock = &it.first->first;
        m_active_chain.SetTip(*m_best_header);
    }

    const CChainParams& GetParams() const override { return m_params; }
    const Consensus::Params& GetConsensus() const override { return m_consensus; }
    VersionBitsCache& VersionBits() const override { return m_versionbits; }
    RecursiveMutex& GetMutex() const override { return m_mutex; }
    CChain& ActiveChain() const override { return m_active_chain; }
    CBlockIndex* ActiveTip() const override { return m_active_chain.Tip(); }
    int ActiveHeight() const override { return m_active_chain.Height(); }
    bool IsInitialBlockDownload() const noexcept override { return m_fdp.ConsumeBool(); }
    const arith_uint256& MinimumChainWork() const override { return m_minimum_chain_work; }
    CBlockIndex* BestHeader() const override { return m_best_header; }
    void SetBestHeader(CBlockIndex* index) override { m_best_header = index; }
    CBlockIndex* LookupBlockIndex(const uint256& hash) override
    {
        BlockMap::iterator it = m_blockmap.find(hash);
        return it == m_blockmap.end() ? nullptr : &it->second;
    }
    const CBlockIndex* LookupBlockIndex(const uint256& hash) const override
    {
        BlockMap::const_iterator it = m_blockmap.find(hash);
        return it == m_blockmap.end() ? nullptr : &it->second;
    }
    bool LoadingBlocks() const override { return m_fdp.ConsumeBool(); }
    bool IsPruneMode() const override { return m_fdp.ConsumeBool(); }
    bool IsBlockPruned(const CBlockIndex& block) const override { return m_fdp.ConsumeBool(); }
    bool ReadBlock(CBlock& block, const FlatFilePos& pos, const std::optional<uint256>& expected_hash) const override
    {
        // TODO: fill out CBlock
        return m_fdp.ConsumeBool();
    }
    bool ReadBlock(CBlock& block, const CBlockIndex& index) const override
    {
        // TODO: fill out CBlock
        return m_fdp.ConsumeBool();
    }
    RawBlockResult ReadRawBlock(const FlatFilePos& pos, std::optional<std::pair<size_t, size_t>> block_part) const override
    {
        if (m_fdp.ConsumeBool()) return util::Unexpected{node::ReadRawError::IO};
        return std::vector<std::byte>{}; // TODO: fill out
    }
    const CBlockIndex* FindForkInGlobalIndex(const CBlockLocator& locator) const override
    {
        return nullptr; // TODO: random CBlockIndex*
    }
    bool ActivateBestChain(BlockValidationState& state, std::shared_ptr<const CBlock> pblock) override
    {
        // TODO: Callbacks, sometimes mock a reorg, set state.
        return m_fdp.ConsumeBool();
    }
    const CBlockIndex* CurrentSnapshotBase() const override
    {
        // TODO: Return "valid" snapshot block index
        return nullptr;
    }
    Assumeutxo CurrentAssumeutxoState() const override
    {
        return m_fdp.PickValueInArray({Assumeutxo::VALIDATED, Assumeutxo::UNVALIDATED, Assumeutxo::INVALID});
    }
    bool ProcessNewBlock(const std::shared_ptr<const CBlock>& block,
                         bool force_processing,
                         bool min_pow_checked,
                         bool* new_block) override
    {
        // TODO: Call BlockChecked with block, state
        // TODO: Add block to store
        *new_block = m_fdp.ConsumeBool();
        return m_fdp.ConsumeBool();
    }
    bool ProcessNewBlockHeaders(std::span<const CBlockHeader> headers,
                                bool min_pow_checked,
                                BlockValidationState& state,
                                const CBlockIndex** ppindex) override
    {
        auto result = m_fdp.PickValueInArray({BlockValidationResult::BLOCK_CACHED_INVALID,
                                              BlockValidationResult::BLOCK_MISSING_PREV,
                                              BlockValidationResult::BLOCK_INVALID_PREV,
                                              BlockValidationResult::BLOCK_HEADER_LOW_WORK,
                                              BlockValidationResult::BLOCK_INVALID_HEADER,
                                              BlockValidationResult::BLOCK_TIME_FUTURE});
        state.Invalid(result, "", "");
        // TODO: Also process properly, a little wonky since the first one must build off of something
        return false;
    }
    MempoolAcceptResult ProcessTransaction(const CTransactionRef& tx, bool test_accept) override
    {
        // TODO: m_result_type, m_state, m_replaced_transactions
        return MempoolAcceptResult::Success(/*replaced_transactions=*/{}, /*vsize=*/0, /*fees=*/0,
                                            /*effective_feerate=*/CFeeRate{0},
                                            /*wtxids_fee_calculations=*/{});
    }
    PackageMempoolAcceptResult ProcessPackage(CTxMemPool& pool,
                                              const Package& txns,
                                              bool test_accept,
                                              const std::optional<CFeeRate>& client_maxfeerate) override
    {
        // TODO: m_state, m_tx_results (some may be missing)
        return PackageMempoolAcceptResult{{}, {}};
    }
    void ReportHeadersPresync(int64_t height, int64_t timestamp) override {}
    std::optional<std::pair<const CBlockIndex*, const CBlockIndex*>> GetHistoricalBlockRange() const override
    {
        // TODO: Valid CBlockIndex*
        return std::nullopt;
    }

private:
    FuzzedDataProvider& m_fdp;
    const CChainParams& m_params;
    const Consensus::Params& m_consensus;
    mutable VersionBitsCache m_versionbits;
    mutable RecursiveMutex m_mutex;
    mutable CChain m_active_chain;
    arith_uint256 m_minimum_chain_work; // TODO: set this
    CBlockIndex* m_best_header{nullptr}; // TODO: set, recalculate this
    // TODO: Things NOT in m_active_chain, how to track
    BlockMap m_blockmap;
    // TODO: Also store CBlocks in a map
};

} // namespace

void initialize_peerman()
{
    static const auto testing_setup{MakeNoLogFileContext<const BasicTestingSetup>(/*chain_type=*/ChainType::REGTEST)};
    (void)testing_setup;
}

FUZZ_TARGET(peerman, .init = initialize_peerman)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    NodeClockContext clock_ctx{1610000000s};

    auto netval = std::make_unique<FuzzedNetValidation>(fuzzed_data_provider, Params());
    NetGroupManager netgroupman{NetGroupManager::NoAsmap()};
    AddrMan addrman{netgroupman, /*deterministic=*/true, /*consistency_check_ratio=*/0};
    ConnmanTestMsg connman{0x1337, 0x1337, addrman, netgroupman, Params(), /*network_active=*/true};
    bilingual_str mempool_error;
    CTxMemPool::Options mempool_opts{};
    mempool_opts.check_ratio = 0;
    mempool_opts.signals = nullptr;
    CTxMemPool mempool{std::move(mempool_opts), mempool_error};
    Assert(mempool_error.empty());
    node::Warnings warnings{};

    auto peerman = PeerManager::make(connman, addrman,
                                     /*banman=*/nullptr, std::move(netval),
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

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 30)
    {
        const std::string random_message_type{fuzzed_data_provider.ConsumeBytesAsString(CMessageHeader::MESSAGE_TYPE_SIZE).c_str()};

        clock_ctx.set(ConsumeTime(fuzzed_data_provider));

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
    signals.SyncWithValidationInterfaceQueue();
    signals.UnregisterValidationInterface(peerman.get());
    connman.StopNodes();
}
