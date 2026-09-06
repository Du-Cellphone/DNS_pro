#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>

enum class WorkerFailurePolicy
{
    FailService,
    Restart,
};

namespace dns::server
{

enum class WorkerFailureCode : uint8_t
{
    UnexpectedStop,
    FatalExit,
    CreateFailed,
    ThreadStartFailed,
    InitFailed,
    InstanceIdExhausted,
    JoinFailed,
};

struct WorkerRecoveryConfig final
{
    WorkerFailurePolicy       policy{WorkerFailurePolicy::FailService};
    size_t                    max_attempts{3};
    std::chrono::milliseconds initial_backoff{100};
    std::chrono::milliseconds max_backoff{5'000};
    std::chrono::milliseconds stability_window{30'000};
};

inline bool is_valid_recovery_config(const WorkerRecoveryConfig &config) noexcept
{
    return config.policy == WorkerFailurePolicy::FailService ||
           (config.policy == WorkerFailurePolicy::Restart && config.max_attempts != 0 && config.initial_backoff.count() >= 0 &&
            config.max_backoff >= config.initial_backoff && config.stability_window.count() >= 0);
}

} // namespace dns::server
