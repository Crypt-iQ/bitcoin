#include <span>
#include <test/fuzz/snapshot_fuzz.h>
#include <util/check.h>

#include <cstddef>
#include <cstdio>
#include <functional>
#include <iostream>

extern "C" {
// Initialize nyx agent
__attribute__((weak)) size_t nyx_init();
// Get the next fuzz input (this will take the snapshot on the first call).
__attribute__((weak)) size_t nyx_get_fuzz_data(uint8_t* data, size_t max_size);
// Reset the vm
__attribute__((weak)) void nyx_release();
}

namespace snapshot_fuzz {

void NyxApiSmokeTest()
{
#ifdef SNAPSHOT_FUZZ
    if (!nyx_init || !nyx_get_fuzz_data || !nyx_release) {
        std::cerr << "Nyx api not linked, make sure to LD_PRELOAD the nyx agent!" << std::endl;
        abort();
    }
#endif
}

Fuzz::Fuzz(std::span<const uint8_t> buffer)
{
#ifdef SNAPSHOT_FUZZ
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
    size_t size = nyx_get_fuzz_data(buffer.data(), m_max_size); // snapshot

    Assert(fn)({buffer.data(), size});

    nyx_release(); // reset vm
#else
    Assert(fn)(m_buffer);
#endif
}

} // namespace snapshot_fuzz
