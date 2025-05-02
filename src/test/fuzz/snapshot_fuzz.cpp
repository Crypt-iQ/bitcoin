// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/check.h>
#include <test/fuzz/snapshot_fuzz.h>

#include <cstddef>
#include <cstdio>
#include <functional>
#include <iostream>
#include <span>

extern "C" {
// Initialize the nyx agent. This will call the GET_HOST_CONFIG kAFL hypercall to query the host
// configuration. It will then call the SET_AGENT_CONFIG hypercall to set the agent's configuration.
__attribute__((weak)) size_t nyx_init();

// Get the next fuzz input. This will take a VM snapshot on the first call. Under-the-hood this calls
// the GET_PAYLOAD hypercall to register our payload buffer and then the USER_FAST_ACQUIRE hypercall.
// USER_FAST_ACQUIRE is what takes the VM snapshot on the first call by internally calling NEXT_PAYLOAD.
// This is called at the beginning of a fuzzing iteration.
__attribute__((weak)) size_t nyx_get_fuzz_data(uint8_t* data, size_t max_size);

// Call the kAFL RELEASE hypercall under-the-hood. This will reset the VM back to the snapshot. This
// is called at the end of a fuzzing iteration.
__attribute__((weak)) void nyx_release();
}

namespace snapshot_fuzz {

void NyxApiSmokeTest()
{
#ifdef SNAPSHOT_FUZZ
    if (!nyx_init || !nyx_get_fuzz_data || !nyx_release) {
        std::cerr << "Nyx API not linked, check that LD_PRELOAD is set!" << std::endl;
        abort();
    }
#endif
}

Fuzz::Fuzz(std::span<const uint8_t> buffer)
{
#ifdef SNAPSHOT_FUZZ
    // Check that the agent code is linked as otherwise we cannot use the kAFL hypercall API.
    // Then initialize the agent so that we can utilize VM snapshots.
    NyxApiSmokeTest();
    m_max_size = nyx_init();
#else
    m_buffer = buffer;
#endif
}

void Fuzz::run(std::function<void(std::span<const uint8_t>)> fn)
{
#ifdef SNAPSHOT_FUZZ
    std::vector<uint8_t> buffer;
    buffer.resize(m_max_size);

    // Snapshot the VM state if this is the very first time calling nyx_get_fuzz_data. Proceed
    // normally, put bytes into buffer and pass the buffer to fn.
    size_t size = nyx_get_fuzz_data(buffer.data(), m_max_size);

    Assert(fn)({buffer.data(), size});

    // Call this to signal that we are done executing this fuzz input. This will restore the VM
    // to the snapshotted state.
    nyx_release();
#else
    Assert(fn)(m_buffer);
#endif
}

} // namespace snapshot_fuzz
