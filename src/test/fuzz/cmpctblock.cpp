// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addrman.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/consensus.h>
#include <net.h>
#include <net_processing.h>
#include <netmessagemaker.h>
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
#include <util/check.h>
#include <util/time.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

TestingSetup* g_setup;

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

    for (int i = 0; i < 2 * COINBASE_MATURITY; ++i) {
        MineBlock(setup.m_node, options);
    }

    setup.m_node.validation_signals->SyncWithValidationInterfaceQueue();
}

} // namespace

void initialize_cmpctblock()
{
    static const auto testing_setup = MakeNoLogFileContext<TestingSetup>();
    g_setup = testing_setup.get();
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

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 1000)
    {
        CSerializedNetMsg net_msg;
        bool set_net_msg = true;

        CallOneOf(
            fuzzed_data_provider,
            [&]() {
                // Send a sendcmpct message, optionally setting hb mode.
                bool hb = fuzzed_data_provider.ConsumeBool();
                net_msg = NetMsg::Make(NetMsgType::SENDCMPCT, /*high_bandwidth=*/hb, /*version=*/CMPCTBLOCKS_VERSION);
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
}
