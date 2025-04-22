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
#include <test/fuzz/util/net.h>
#include <test/util/mining.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <util/fs_helpers.h>
#include <util/time.h>
#include <validationinterface.h>

#include <filesystem>
#include <ios>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace {

//! One for each block the fuzzer generates.
struct BlockInfo {
    std::shared_ptr<CBlock> block;
    uint256 hash;
    uint32_t height;
};

} // namespace

void initialize_cmpctblock() {}

FUZZ_TARGET(cmpctblock, .init=initialize_cmpctblock)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    // Create a TestingSetup with a pre-set mock time. The mock time must be set here
    // to avoid fuzzer-related warnings about non-determinism.
    const auto mock_start_time{1610000000};
    const auto testing_setup = MakeNoLogFileContext<const TestingSetup>(
        /*chain_type=*/ChainType::REGTEST,
        {.extra_args = {strprintf("-mocktime=%d", mock_start_time).c_str()}}); 

    uint32_t g_nBits = Params().GenesisBlock().nBits;
    uint32_t g_height;
    uint256 g_tip;

    // Register PeerManager so the BlockChecked callback can be invoked. Also, reset IBD.
    auto setup = testing_setup.get();
    setup->m_node.validation_signals->RegisterValidationInterface(setup->m_node.peerman.get());
    setup->m_node.validation_signals->SyncWithValidationInterfaceQueue();
    WITH_LOCK(::cs_main, g_tip = setup->m_node.chainman->ActiveChain().Tip()->GetBlockHash());
    WITH_LOCK(::cs_main, g_height = setup->m_node.chainman->ActiveChain().Height());
    auto& chainman = static_cast<TestChainstateManager&>(*setup->m_node.chainman);
    chainman.ResetIbd();

    LOCK(NetEventsInterface::g_msgproc_mutex); 

    std::vector<CNode*> peers;
    auto& connman = *static_cast<ConnmanTestMsg*>(setup->m_node.connman.get()); 
    for (int i = 0; i < 3; ++i) {
        peers.push_back(ConsumeNodeAsUniquePtr(fuzzed_data_provider, i).release());
        CNode& p2p_node = *peers.back();
        FillNode(fuzzed_data_provider, connman, p2p_node);
        connman.AddTestNode(p2p_node);
    }

    // Set time so that we might be close to the tip's time.
    SetMockTime(ConsumeTime(fuzzed_data_provider));

    // Stores blocks generated this iteration.
    std::vector<BlockInfo> info;

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

        const auto new_time = WITH_LOCK(::cs_main, return setup->m_node.chainman->ActiveChain().Tip()->GetMedianTimePast() + 1);

        CBlockHeader header;
        header.nNonce = 0;
        header.hashPrevBlock = prev;
        header.nBits = g_nBits;
        header.nTime = new_time;
        header.nVersion = fuzzed_data_provider.ConsumeIntegral<int32_t>();

        std::shared_ptr<CBlock> block = std::make_shared<CBlock>();
        *block = header;

        // Randomly provide a valid BIP34 coinbase.
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
            // Otherwise, fill the block with (likely invalid) transactions.
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
                    PrefilledTransaction prefilledtx = {/*index=*/prefill_idx, txref}
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

                        block_txn.txn.push_back(cblock->vtx[i])
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
            setup->m_node.peerman->SendMessages(&random_node);
        }
    }

    setup->m_node.validation_signals->SyncWithValidationInterfaceQueue();
    setup->m_node.connman->StopNodes();
}
