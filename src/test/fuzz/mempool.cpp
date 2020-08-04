// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparamsbase.h>
#include <primitives/transaction.h>
#include <txmempool.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/setup_common.h>

#include <vector>
#include <optional>

void initialize()
{
    static TestingSetup setup{CBaseChainParams::REGTEST, {"-nodebuglogfile"}};
}

void test_one_input(const std::vector<uint8_t>& buffer)
{
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    CTxMemPool mpool;
   
    while (fuzzed_data_provider.ConsumeBool()) {
	switch (fuzzed_data_provider.ConsumeIntegralInRange<uint8_t>(0, 1)) {
	case 0: {
	    std::optional<CMutableTransaction> mtx = ConsumeDeserializable<CMutableTransaction>(fuzzed_data_provider);
	    if (!mtx) {
	        break;
	    }
	    const CTransaction ctx{*mtx};
	    LOCK2(cs_main, mpool.cs);
	    mpool.addUnchecked(ConsumeTxMemPoolEntry(fuzzed_data_provider, ctx));
	    break;
	}
	case 1: {
	    std::optional<CMutableTransaction> mtx = ConsumeDeserializable<CMutableTransaction>(fuzzed_data_provider);
	    if (!mtx) {
		break;
	    }
	    const CTransaction ctx{*mtx};
	    MemPoolRemovalReason reason;
	    switch (fuzzed_data_provider.ConsumeIntegralInRange<uint8_t>(0, 5)) {
	    case 0: {
	        reason = MemPoolRemovalReason::EXPIRY;
	    	break;
	    }
	    case 1: {
	        reason = MemPoolRemovalReason::SIZELIMIT;
    		break;			
	    }
	    case 2: {
		reason = MemPoolRemovalReason::REORG;
		break;
 	    }
	    case 3: {
		reason = MemPoolRemovalReason::BLOCK;
		break;
	    }
	    case 4: {
		reason = MemPoolRemovalReason::CONFLICT;
		break;
	    }
	    case 5: {
		reason = MemPoolRemovalReason::REPLACED;
		break;
            }
	    }

	    LOCK2(cs_main, mpool.cs);
	    mpool.removeRecursive(ctx, reason);
	    break;	
	}
	}
    }
}
