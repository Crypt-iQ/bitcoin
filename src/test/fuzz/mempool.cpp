// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/transaction.h>
#include <txmempool.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <vector>
#include <optional>

void test_one_input(const std::vector<uint8_t>& buffer)
{
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    CTxMemPool mpool;

    // AcceptToMemoryPool
    // removeForBlock
    // 
    // need block disconnected / connected callbacks...
    
    while (fuzzed_data_provider.ConsumeBool()) {
	    // args to AcceptToMemoryPool or removeForBlock...
	    // bool AcceptToMemoryPool(CTxMemPool&, TxValidationState&, CTransactionRef&,
	    // std::list<CTransactionRef>*,bool,CAmount,bool)
	    // 
	    // void addUnchecked(const CTxMemPoolEntry&, bool) EXCL(cs, cs_main)
	    //
	    // void removeForBlock(const std::vector<CTransactionRef>&,unsigned int) EXCL(cs)
	switch (fuzzed_data_provider.ConsumeIntegralInRange<int>(0, 1)) {
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
	    // LOCK2(cs_main, mpool.cs);
	    std::optional<CMutableTransaction mtx = ConsumeDeserializable<CMutableTransaction(fuzzed_data_provider);
	    if (!mtx) {
		break;
	    }
	    const CTransaction ctx{*mtx};

	    // Choose a dummy reason
	    // TODO: can also use removeForBlock with ConsumeBytes<CTransactionRef>?
	
	    auto reason = fuzzed_data_provider.ConsumeEnum<MemPoolRemovalReason>()

	    LOCK2(cs_main, mpool.cs);
	    mpool.removeRecursive(ctx, reason);
	    break;	
	}
	}
    }
}
