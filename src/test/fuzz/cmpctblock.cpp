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

#include <exception>
#include <filesystem>
#include <ios>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace {

std::string dirstring{"-testdatadir="};

uint256 g_tip;
uint32_t g_nBits;
uint32_t g_height;
std::filesystem::path g_root_path;
std::filesystem::path g_tmp_path;

//! The list of possible fuzzer commands.
enum Command : uint8_t {
    CMPCTBLOCK,
    BLOCKTXN,
    HEADERS,
    SENDCMPCT,
    MINE_BLOCK,
};

//! One of these is created for every block the fuzz harness generates.
struct BlockInfo {
    std::shared_ptr<CBlock> block;
    uint256 hash;
    uint32_t height;
};

} // namespace

void initialize_cmpctblock()
{
    g_root_path = std::filesystem::current_path() / "cmpctblock_init";
    g_tmp_path = std::filesystem::current_path() / "cmpctblock_tmp";
    std::filesystem::create_directory(g_root_path);

    auto root_string = dirstring + g_root_path.string();

    const auto initial_testing_setup = MakeNoLogFileContext<const TestingSetup>(
        /*chain_type=*/ChainType::REGTEST,
        {.extra_args = {root_string.c_str()}});

    for (int i = 0; i < 2 * COINBASE_MATURITY; i++) {
        MineBlock(initial_testing_setup.get()->m_node, {});
    }

    g_nBits = Params().GenesisBlock().nBits;
}

FUZZ_TARGET(cmpctblock, .init=initialize_cmpctblock)
{
    SeedRandomStateForTest(SeedRand::ZEROS);

    // coins_db_in_memory
    // block_tree_db_in_memory

    std::filesystem::remove_all(g_tmp_path);
    std::filesystem::copy(g_root_path, g_tmp_path, std::filesystem::copy_options::recursive);

    auto tmp_string = dirstring + g_tmp_path.string();

    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    const auto mock_start_time{1610000000};

    const auto testing_setup = MakeNoLogFileContext<const TestingSetup>(
        /*chain_type=*/ChainType::REGTEST,
        {.extra_args = {tmp_string.c_str(),
                        strprintf("-mocktime=%d", mock_start_time).c_str()}}); 

    auto setup = testing_setup.get();

    setup->m_node.validation_signals->RegisterValidationInterface(setup->m_node.peerman.get());
    setup->m_node.validation_signals->SyncWithValidationInterfaceQueue();

    WITH_LOCK(::cs_main, g_tip = setup->m_node.chainman->ActiveChain().Tip()->GetBlockHash());
    WITH_LOCK(::cs_main, g_height = setup->m_node.chainman->ActiveChain().Height());

    ConnmanTestMsg& connman = *static_cast<ConnmanTestMsg*>(setup->m_node.connman.get());
    auto& chainman = static_cast<TestChainstateManager&>(*setup->m_node.chainman);
    chainman.ResetIbd();

    std::vector<BlockInfo> info;

    LOCK(NetEventsInterface::g_msgproc_mutex);

    std::vector<CNode*> peers;
    static NodeId id{0};
    for (int i = 0; i < 3; i++) {
        peers.push_back(ConsumeNodeAsUniquePtr(fuzzed_data_provider, id++).release());
        CNode& p2p_node = *peers.back();
        FillNode(fuzzed_data_provider, connman, p2p_node);
        connman.AddTestNode(p2p_node);
    }

    // Set time so that we will be close to the tip's time, some of the time.
    const auto mock_time = ConsumeTime(fuzzed_data_provider);
    SetMockTime(mock_time);

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
            // Otherwise, just fill the block with (likely invalid) transactions.
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

        uint8_t fuzzed_command = fuzzed_data_provider.ConsumeIntegralInRange<uint8_t>(CMPCTBLOCK, MINE_BLOCK);
        switch (fuzzed_command) {
        case CMPCTBLOCK: {
            std::shared_ptr<CBlock> cblock;

            // Sometimes pick from an existing block and the rest of the time create a new block.
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
                // Some of the time, don't modify the compact block that the constructor makes.
                net_msg = NetMsg::Make(NetMsgType::CMPCTBLOCK, cmpctBlock);
                break;
            }

            // The rest of the time, populate prefilledtxns and shorttxids while keeping hashMerkleRoot the same.
            // Choose a random number of PrefilledTransaction to include, starting in-order from vtx[1].
            size_t num_prefilled = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(2, num_txs);

            for (size_t i = 1; i < num_prefilled; i++) {
                CTransactionRef txref = cblock->vtx[i];

                // TODO: Fuzz PrefilledTransaction index field.
                PrefilledTransaction prefilledtx = {/*index=*/0, txref};
                cmpctBlock.prefilledtxn.push_back(std::move(prefilledtx));
            }

            // Erase from the front of shorttxids since these transactions have been prefilled.
            for (size_t i = 0; i < num_prefilled - 1; i++) {
                cmpctBlock.shorttxids.erase(cmpctBlock.shorttxids.begin());
            }

            net_msg = NetMsg::Make(NetMsgType::CMPCTBLOCK, cmpctBlock);

            break;
        }

        case BLOCKTXN: {
            // If no blocks exist, return.
            size_t num_blocks = info.size();
            if (num_blocks == 0) {
                return;
            }

            // Fetch a pre-existing block and determine which transactions to send over.
            size_t index = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, num_blocks - 1);
            BlockInfo block_info = info[index];
            BlockTransactions block_txn;
            block_txn.blockhash = block_info.hash;
            std::shared_ptr<CBlock> cblock = block_info.block;

            size_t num_txs = cblock->vtx.size();

            if (num_txs > 1) {
                for (size_t i = 1; i < num_txs; i++) {
                    block_txn.txn.push_back(cblock->vtx[i]);
                }
            }

            net_msg = NetMsg::Make(NetMsgType::BLOCKTXN, block_txn);

            break;
        }

        case HEADERS: {
            size_t num_blocks = info.size();
            if (num_blocks == 0) {
                return;
            }

            // Choose a random, existing block that the fuzzer has created and send a HEADERS message for it.
            size_t index = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, num_blocks - 1);
            CBlock block = *info[index].block;
            std::vector<CBlock> headers;
            headers.push_back(block);

            net_msg = NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(headers));

            break;
        }

        case SENDCMPCT: {
            bool hb = fuzzed_data_provider.ConsumeBool();

            // TODO: Extract CMPCTBLOCKS_VERSION from net_processing.cpp
            net_msg = NetMsg::Make(NetMsgType::SENDCMPCT, /*high_bandwidth=*/hb, /*version=*/uint64_t(2));

            break;
        }

        case MINE_BLOCK: {
            BlockInfo blockinfo = create_block();
            info.push_back(blockinfo);

            return;
        }
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
