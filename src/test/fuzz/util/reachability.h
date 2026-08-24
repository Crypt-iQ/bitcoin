// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_FUZZ_UTIL_REACHABILITY_H
#define BITCOIN_TEST_FUZZ_UTIL_REACHABILITY_H

#include <source_location>
#include <string_view>

/// Record whether a reachability goal is satisfied by at least one fuzz input.
///
/// Goals are identified by their call site and aggregated across the lifetime
/// of the fuzz process. A goal is tracked only after its call site is executed,
/// so calls should generally be unconditional and near the end of the target.
/// The message describes the condition in the shutdown report.
/// Set FUZZ_ENFORCE_REACHABILITY=1 to fail at shutdown if a tracked goal was
/// never satisfied.
void ReachabilityGoal(
    bool reached,
    std::string_view message,
    std::source_location location = std::source_location::current());

#endif // BITCOIN_TEST_FUZZ_UTIL_REACHABILITY_H
