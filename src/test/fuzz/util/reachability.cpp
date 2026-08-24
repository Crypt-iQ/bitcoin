// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sync.h>
#include <test/fuzz/util/reachability.h>

#include <compare>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <map>
#include <string>
#include <string_view>

namespace {
struct GoalId {
    std::string_view file_name;
    std::uint_least32_t line;
    std::uint_least32_t column;

    auto operator<=>(const GoalId&) const = default;
};

struct GoalState {
    std::string message;
    bool reached{false};

    explicit GoalState(std::string_view message) : message{message} {}
};

class ReachabilityTracker
{
public:
    ReachabilityTracker()
    {
        const char* enforce{std::getenv("FUZZ_ENFORCE_REACHABILITY")};
        if (!enforce || std::string_view{enforce} == "0") return;
        if (std::string_view{enforce} == "1") {
            m_enforce = true;
            return;
        }
        std::fputs("FUZZ_ENFORCE_REACHABILITY must be 0 or 1.\n", stderr);
        std::abort();
    }

    ~ReachabilityTracker()
    {
        LOCK(m_mutex);
        bool all_reached{true};
        for (const auto& [id, goal] : m_goals) {
            std::cerr << (goal.reached ? "PASS" : "FAIL") << " reachability goal \""
                      << goal.message << "\" at " << id.file_name << ':' << id.line << ':' << id.column << '\n';
            all_reached &= goal.reached;
        }
        if (m_enforce && !all_reached) {
            std::cerr.flush();
            std::_Exit(EXIT_FAILURE);
        }
    }

    void Observe(
        bool reached,
        std::string_view message,
        std::source_location location) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        const GoalId id{
            .file_name = location.file_name(),
            .line = location.line(),
            .column = location.column(),
        };
        LOCK(m_mutex);
        auto& goal{m_goals.try_emplace(id, message).first->second};
        goal.reached |= reached;
    }

private:
    Mutex m_mutex;
    std::map<GoalId, GoalState> m_goals GUARDED_BY(m_mutex);
    bool m_enforce{false};
};

ReachabilityTracker g_reachability_tracker;
} // namespace

void ReachabilityGoal(bool reached, std::string_view message, std::source_location location)
{
    g_reachability_tracker.Observe(reached, message, location);
}
