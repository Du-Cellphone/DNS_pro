#pragma once

#include "FilterPublication.h"
#include "common/Expected.h"

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
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

struct FilterUpdateControllerTestPeer;

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

struct FilterUpdateLimits final
{
    static constexpr size_t kDefaultMaximumRuleCount           = 100'000;
    static constexpr size_t kDefaultMaximumNormalizedRuleBytes = 16U * 1024U * 1024U;
    static constexpr size_t kDefaultMaximumQueuedRuleBytes     = 64U * 1024U * 1024U;

    size_t maximum_rule_count{kDefaultMaximumRuleCount};
    size_t maximum_normalized_rule_bytes{kDefaultMaximumNormalizedRuleBytes};
    size_t maximum_queued_rule_bytes{kDefaultMaximumQueuedRuleBytes};
};

enum class FilterUpdateErrorCode
{
    ServiceNotRunning,
    ControlPlaneDisabled,
    ShuttingDown,
    BuildFailed,
    GenerationExhausted,
    QueueFull,
    RuleCountLimitExceeded,
    RuleBytesLimitExceeded,
    QueueBytesLimitExceeded,
    InternalError,
};

struct FilterUpdateError
{
    FilterUpdateErrorCode                      code{FilterUpdateErrorCode::InternalError};
    std::optional<Filter::BlocklistBuildError> build_error;
    size_t                                     actual{0};
    size_t                                     limit{0};

    bool operator==(const FilterUpdateError &) const = default;
};

using FilterUpdateResult = std::expected<FilterVersion, FilterUpdateError>;
using FilterUpdateFuture = std::future<FilterUpdateResult>;

enum class FilterSuccessorCompletionResult : uint8_t
{
    Completed,
    ReclaimerUnavailable,
    WriterStillRunning,
    InternalError,
};

struct FilterRuleMeasurement final
{
    size_t raw_bytes{0};
    size_t normalized_bytes{0};
};

[[nodiscard]] std::expected<FilterRuleMeasurement, FilterUpdateError> validate_filter_rule_set(std::span<const std::string> rules,
                                                                                               const FilterUpdateLimits    &limits = {}) noexcept;

class FilterUpdateController final
{
public:
    using Builder = std::function<FilterSnapshotBuild(std::span<const std::string>, FilterGeneration, std::stop_token)>;

    static constexpr size_t kMaximumPendingUpdates = 64;

    explicit FilterUpdateController(FilterPublicationState &publication, Builder builder = {}, FilterUpdateLimits limits = {});
    ~FilterUpdateController();

    FilterUpdateController(const FilterUpdateController &)            = delete;
    FilterUpdateController &operator=(const FilterUpdateController &) = delete;

    [[nodiscard]] FilterUpdateFuture submit_replace(std::vector<std::string> rules);
    // One-shot blocking A-thread body. A sealed runner remains alive until the
    // teardown coordinator requests the final active-owner detach.
    [[nodiscard]] FilterRunnerResult run(std::stop_token stop_token, FilterRunnerObserver *observer = nullptr) noexcept;
    void                             seal() noexcept;
    void                             request_terminal_detach() noexcept;
    void                             close() noexcept { request_terminal_detach(); }
    [[nodiscard]] bool               wait_until_sealed(std::stop_token stop_token = {}) noexcept;

    // Emergency publication successor. The caller must first join A and make
    // the committed generation converge through B or the emergency reclaimer.
    // It completes the stable promise journal without changing publication.
    [[nodiscard]] FilterSuccessorCompletionResult complete_committed_by_successor() noexcept;

    // Deterministic lifecycle seam: the next successful commit is left in the
    // stable journal and A exits through its fatal epilogue.
    void inject_postcommit_failure_for_testing() noexcept;

    [[nodiscard]] FilterVersion current_version() const noexcept { return publication_.current_version(); }

private:
    friend struct FilterUpdateControllerTestPeer;

    enum class CommandPhase : uint8_t
    {
        Queued,
        Building,
        Publishing,
        Committed,
        Completed,
    };

    struct Command
    {
        Command(std::vector<std::string> value_rules, size_t value_accounted_bytes)
            : rules(std::move(value_rules))
            , accounted_bytes(value_accounted_bytes)
        {
        }

        std::vector<std::string>         rules;
        size_t                           accounted_bytes{0};
        CommandPhase                     phase{CommandPhase::Queued};
        std::optional<FilterVersion>     target;
        std::optional<FilterVersion>     published;
        std::promise<FilterUpdateResult> completion;
    };

    [[nodiscard]] FilterUpdateResult apply(Command &command, std::stop_token stop_token) noexcept;
    static void                      complete(Command &command, FilterUpdateResult result) noexcept;
    void                             cancel_pending(FilterUpdateErrorCode code) noexcept;
    void                             finish_run() noexcept;
    void                             reconcile_inflight_after_writer_exit() noexcept;

    FilterPublicationState              &publication_;
    Builder                              builder_;
    FilterUpdateLimits                   limits_;
    mutable std::mutex                   mutex_;
    std::condition_variable_any          wakeup_;
    std::condition_variable              runner_stopped_;
    std::deque<std::unique_ptr<Command>> pending_;
    std::unique_ptr<Command>             inflight_;
    size_t                               queued_rule_bytes_{0};
    std::stop_source                     build_stop_source_;
    bool                                 sealed_{false};
    bool                                 sealed_acknowledged_{false};
    bool                                 terminal_detach_requested_{false};
    bool                                 runner_active_{false};
    std::atomic<bool>                    fail_after_commit_for_testing_{false};
};

} // namespace dns::server
