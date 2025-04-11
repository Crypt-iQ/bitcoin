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
#include <sync.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/fuzz/util/net.h>
#include <test/util/mining.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <util/time.h>
#include <validationinterface.h>

#include <ios>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace {
const TestingSetup* g_setup;

uint256 g_tip;

uint32_t g_nBits;
} // namespace

enum Command : uint8_t {
    SEND_CMPCTBLOCK,
    SEND_BLOCKTXN,
    SEND_HEADERS,
    MINE_BLOCK,
};

void initialize_cmpctblock()
{
    static const auto testing_setup = MakeNoLogFileContext<const TestingSetup>(
        /*chain_type=*/ChainType::REGTEST,
        {.extra_args = {"-txreconciliation"}});
    g_setup = testing_setup.get();
    for (int i = 0; i < 2 * COINBASE_MATURITY; i++) {
        MineBlock(g_setup->m_node, {});
    }
    g_setup->m_node.validation_signals->SyncWithValidationInterfaceQueue();

    WITH_LOCK(::cs_main, g_tip = g_setup->m_node.chainman->ActiveChain().Tip()->GetBlockHash());

    // Record nBits so that the fuzzer doesn't need to guess it.
    g_nBits = Params().GenesisBlock().nBits;
}

FUZZ_TARGET(cmpctblock, .init = initialize_cmpctblock)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    ConnmanTestMsg& connman = *static_cast<ConnmanTestMsg*>(g_setup->m_node.connman.get());
    auto& chainman = static_cast<TestChainstateManager&>(*g_setup->m_node.chainman);
    SetMockTime(1610000000); // any time to successfully reset ibd
    chainman.ResetIbd();

    // NOTE: The block headers that this fuzzer creates pollute global state in blockman.
    std::vector<std::shared_ptr<CBlock>> blocks;
    std::vector<uint256> block_hashes;

    LOCK(NetEventsInterface::g_msgproc_mutex);

    std::vector<CNode*> peers;
    static NodeId id{0};
    for (int i = 0; i < 3; i++) {
        peers.push_back(ConsumeNodeAsUniquePtr(fuzzed_data_provider, id++).release());
        CNode& p2p_node = *peers.back();

        FillNode(fuzzed_data_provider, connman, p2p_node);

        connman.AddTestNode(p2p_node);
    }

    // The mock time needs to be set so that the CanDirectFetch() check can be passed.
    const auto mock_time = ConsumeTime(fuzzed_data_provider);
    SetMockTime(mock_time);

    auto create_block = [&]() {
        CBlockHeader header;
        header.nNonce = 0;

        // The hashPrevBlock will be g_tip some of the time and a random, existing block hash that the fuzzer
        // mined in an earlier iteration the rest of the time.
        uint256 prev;
        if (fuzzed_data_provider.ConsumeBool() || block_hashes.size() == 0) {
            prev = g_tip;
        } else {
            size_t index = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, block_hashes.size() - 1);
            prev = block_hashes[index];
        }

        header.hashPrevBlock = prev;
        header.nBits = g_nBits;

        const auto new_time = WITH_LOCK(::cs_main, return g_setup->m_node.chainman->ActiveChain().Tip()->GetMedianTimePast() + 1);
        header.nTime = new_time;
        header.nVersion = fuzzed_data_provider.ConsumeIntegral<int32_t>();

        std::shared_ptr<CBlock> block = std::make_shared<CBlock>();
        *block = header;

        // TODO: Some of the time, make valid transactions so the block can be accepted. This requires us
        //       to keep a pool of mature UTXOs.
        uint8_t num_txns = fuzzed_data_provider.ConsumeIntegralInRange<uint8_t>(1, 10);
        for (int i = 0; i < num_txns; i++) {
            CMutableTransaction tx = ConsumeTransaction(fuzzed_data_provider, std::nullopt);
            block->vtx.push_back(MakeTransactionRef(tx));
        }

        bool mutated;
        block->hashMerkleRoot = BlockMerkleRoot(*block, &mutated);

        // TODO: Extract function... this is copied from FinalizeHeader in p2p_headers_presync.cpp
        while (!CheckProofOfWork(header.GetHash(), header.nBits, chainman.GetParams().GetConsensus()))
            ++(header.nNonce);

        return block;
    };

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 30)
    {
        CSerializedNetMsg net_msg;

        uint8_t fuzzed_command = fuzzed_data_provider.ConsumeIntegralInRange<uint8_t>(SEND_CMPCTBLOCK, MINE_BLOCK);
        switch (fuzzed_command) {
        case SEND_CMPCTBLOCK: {
            std::shared_ptr<CBlock> cblock;

            // Sometimes pick from an existing block and the rest of the time create a new block.
            if (fuzzed_data_provider.ConsumeBool() && blocks.size() != 0) {
                size_t index = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, blocks.size() - 1);
                cblock = blocks[index];
            } else {
                std::shared_ptr<CBlock> block = create_block();
                cblock = block;
                blocks.push_back(block);
                block_hashes.push_back(block->GetHash());
            }

            uint64_t nonce = fuzzed_data_provider.ConsumeIntegral<uint64_t>();
            CBlockHeaderAndShortTxIDs cmpctBlock(*cblock, nonce);

            // Populate prefilledtxn and shorttxids such that the calculated merkle branch matches the header.
            // TODO: go crazy and have mutation and invalid merkle branches.
            size_t num_txs = cblock->vtx.size();

            if (fuzzed_data_provider.ConsumeBool() && num_txs > 1) {
                // For now, these prefilled_txns will all have index = 0 and they will always be in order.
                // TODO: Fuzz PrefilledTransaction indices.
                size_t num_prefilled_txns = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(2, num_txs);

                // Since the constructor filled in the first PrefilledTransaction, start at i=1.
                for (size_t i = 1; i < num_prefilled_txns; i++) {
                    CTransactionRef txref = cblock->vtx[i];
                    PrefilledTransaction prefilledtx = {/*index=*/0, txref};
                    cmpctBlock.prefilledtxn.push_back(std::move(prefilledtx));
                }

                // If we've selected a transaction to be prefilled, then erase it from shorttxids. This is
                // necessary in order for the block to be reconstructed properly.
                for (size_t i = 0; i < num_prefilled_txns - 1; i++) {
                    cmpctBlock.shorttxids.erase(cmpctBlock.shorttxids.begin());
                }
            }

            net_msg = NetMsg::Make(NetMsgType::CMPCTBLOCK, cmpctBlock);

            break;
        }

        case SEND_BLOCKTXN: {
            // If no blocks exist, return.
            size_t num_hashes = block_hashes.size();
            if (num_hashes == 0) {
                break;
            }

            // Fetch a pre-existing block and determine which transactions to send over.
            size_t index = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, num_hashes - 1);

            BlockTransactions block_txn;
            block_txn.blockhash = block_hashes[index];

            std::shared_ptr<CBlock> cblock = blocks[index];

            // We assume that the block has at least one prefilled txn. We then send a random number of transactions
            // over that could potentially help in reconstructing the block if the fuzzer guesses the correct amount
            // to include.
            // TODO: Make less hacky so that this code is aware of how many transactions to fill in.
            size_t num_txs = cblock->vtx.size();

            if (num_txs > 1) {
                // Select which txns from the block to send. Since the first prefilled txn is already filled-in at index=0,
                // we only do this if the number of transactions in the block is greater than 1.
                for (size_t i = 1; i < num_txs; i++) {
                    block_txn.txn.push_back(cblock->vtx[i]);
                }
            }

            net_msg = NetMsg::Make(NetMsgType::BLOCKTXN, block_txn);

            break;
        }

        case SEND_HEADERS: {
            size_t num_hashes = block_hashes.size();
            if (num_hashes == 0) {
                break;
            }

            // Choose a random, existing block that the fuzzer has created and send a HEADERS message for it.
            size_t index = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, num_hashes - 1);
            CBlock block = *blocks[index];

            std::vector<CBlock> headers;
            headers.push_back(block);

            net_msg = NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(headers));

            break;
        }

        case MINE_BLOCK: {
            std::shared_ptr<CBlock> block = create_block();
            blocks.push_back(block);
            block_hashes.push_back(block->GetHash());

            break;
        }
        }

        // TODO: Re-enable multiple peers.
        CNode& random_node = *peers[0]; // *PickValue(fuzzed_data_provider, peers);


        connman.FlushSendBuffer(random_node);
        (void)connman.ReceiveMsgFrom(random_node, std::move(net_msg));

        bool more_work{true};
        while (more_work) {
            random_node.fPauseSend = false;

            try {
                more_work = connman.ProcessMessagesOnce(random_node);
            } catch (const std::ios_base::failure&) {
            }
            g_setup->m_node.peerman->SendMessages(&random_node);
        }
    }

    g_setup->m_node.validation_signals->SyncWithValidationInterfaceQueue();
    g_setup->m_node.connman->StopNodes();
}
