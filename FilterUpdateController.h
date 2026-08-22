#pragma once

#include "FilterContext.h"
#include "common/Expected.h"

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <utility>
#include <vector>

namespace dns::server
{

enum class FilterRunnerReadyCode
{
    Ready,
    AlreadyRunning,
};

struct FilterRunnerReadyResult
{
    FilterRunnerReadyCode code{FilterRunnerReadyCode::Ready};
};

enum class FilterRunnerExitCode
{
    RequestedStop,
    FatalExit,
};

struct FilterRunnerResult
{
    FilterRunnerExitCode code{FilterRunnerExitCode::RequestedStop};
};

class FilterRunnerObserver
{
public:
    virtual ~FilterRunnerObserver()                                    = default;
    virtual void report_ready(FilterRunnerReadyResult result) noexcept = 0;
};

struct FilterVersion
{
    FilterGeneration generation{0};
    size_t           rule_count{0};

    bool operator==(const FilterVersion &) const = default;
};

enum class FilterUpdateErrorCode
{
    ServiceNotRunning,
    ControlPlaneDisabled,
    ShuttingDown,
    BuildFailed,
    GenerationExhausted,
    QueueFull,
    InternalError,
};

struct FilterUpdateError
{
    FilterUpdateErrorCode                      code{FilterUpdateErrorCode::InternalError};
    std::optional<Filter::BlocklistBuildError> build_error;

    bool operator==(const FilterUpdateError &) const = default;
};

using FilterUpdateResult = std::expected<FilterVersion, FilterUpdateError>;
using FilterUpdateFuture = std::future<FilterUpdateResult>;

class FilterUpdateController final
{
public:
    using Builder = std::function<FilterSnapshotBuild(std::span<const std::string>, FilterGeneration, std::stop_token)>;

    static constexpr size_t kMaximumPendingUpdates = 64;

    explicit FilterUpdateController(FilterSnapshot initial_snapshot, Builder builder = {});
    ~FilterUpdateController();

    FilterUpdateController(const FilterUpdateController &)            = delete;
    FilterUpdateController &operator=(const FilterUpdateController &) = delete;

    [[nodiscard]] FilterUpdateFuture submit_replace(std::vector<std::string> rules);
    // One-shot blocking runner. The caller owns the invoking thread and must
    // keep this controller alive until that thread has been joined.
    [[nodiscard]] FilterRunnerResult run(std::stop_token stop_token, FilterRunnerObserver *observer = nullptr) noexcept;
    void                             close() noexcept;

    [[nodiscard]] const FilterSnapshotSlot    &snapshot_slot() const noexcept { return active_snapshot_; }
    [[nodiscard]] FilterSnapshot               snapshot() const noexcept;
    [[nodiscard]] std::optional<FilterVersion> current_version() const noexcept;

private:
    struct Command
    {
        explicit Command(std::vector<std::string> value_rules)
            : rules(std::move(value_rules))
        {
        }

        std::vector<std::string>         rules;
        std::promise<FilterUpdateResult> completion;
    };

    [[nodiscard]] FilterUpdateResult apply(std::span<const std::string> rules, std::stop_token stop_token) noexcept;
    static void                      complete(Command &command, FilterUpdateResult result) noexcept;
    void                             finish_run() noexcept;

    mutable std::mutex                   mutex_;
    std::condition_variable_any          wakeup_;
    std::condition_variable              runner_stopped_;
    std::deque<std::unique_ptr<Command>> pending_;
    FilterSnapshotSlot                   active_snapshot_{nullptr};
    Builder                              builder_;
    std::stop_source                     build_stop_source_;
    bool                                 closed_{false};
    bool                                 runner_active_{false};
};

} // namespace dns::server
