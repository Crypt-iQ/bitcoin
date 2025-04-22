#ifndef BITCOIN_TEST_FUZZ_SNAPSHOT_FUZZ_H
#define BITCOIN_TEST_FUZZ_SNAPSHOT_FUZZ_H

#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>

#include <test/fuzz/fuzz.h>

#ifdef SNAPSHOT_FUZZ
extern "C" __attribute__((weak)) void nyx_printf(const char*, ...);
#else
static void nyx_printf(const char*, ...) {}
#endif

namespace snapshot_fuzz {
class Fuzz
{
#ifdef SNAPSHOT_FUZZ
    size_t m_max_size;
#else
    std::span<const uint8_t> m_buffer;
#endif

public:
    Fuzz(std::span<const uint8_t> buffer);

    ~Fuzz() = default;

    void run(std::function<void(std::span<const uint8_t>)> fn);
};
} // namespace snapshot_fuzz

#define SNAPSHOT_FUZZ_TARGET(target)                                 \
    static void target##_initialize() {}                             \
    FUZZ_TARGET(target, .init = target##_initialize, .hidden = true) \
    {                                                                \
        snapshot_fuzz::Fuzz fuzz{buffer};                            \
        target(fuzz);                                                \
    }

#endif
