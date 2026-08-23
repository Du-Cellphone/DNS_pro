#include "FilterUpdateController.h"

#include "protocol/DomainName.h"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <utility>

namespace dns::server
{
namespace
{

FilterUpdateResult update_error(FilterUpdateErrorCode code, std::optional<Filter::BlocklistBuildError> build_error = std::nullopt, size_t actual = 0,
                                size_t limit = 0)
{
    return std::unexpected(FilterUpdateError{code, std::move(build_error), actual, limit});
}

FilterUpdateFuture ready_error(FilterUpdateError error)
{
    std::promise<FilterUpdateResult> promise;
    auto                             future = promise.get_future();
    promise.set_value(std::unexpected(std::move(error)));
    return future;
}

size_t saturated_add(size_t lhs, size_t rhs) noexcept
{
    return rhs > std::numeric_limits<size_t>::max() - lhs ? std::numeric_limits<size_t>::max() : lhs + rhs;
}

struct InjectedPostcommitFailure final
{
};

} // namespace

std::expected<FilterRuleMeasurement, FilterUpdateError> validate_filter_rule_set(std::span<const std::string> rules,
                                                                                 const FilterUpdateLimits    &limits) noexcept
{
    try
    {
        if (rules.size() > limits.maximum_rule_count)
        {
            return std::unexpected(
                FilterUpdateError{FilterUpdateErrorCode::RuleCountLimitExceeded, std::nullopt, rules.size(), limits.maximum_rule_count});
        }

        FilterRuleMeasurement measured;
        for (const std::string &rule : rules)
        {
            if (rule.size() > limits.maximum_normalized_rule_bytes - std::min(measured.raw_bytes, limits.maximum_normalized_rule_bytes))
            {
                return std::unexpected(FilterUpdateError{FilterUpdateErrorCode::RuleBytesLimitExceeded, std::nullopt,
                                                         saturated_add(measured.raw_bytes, rule.size()), limits.maximum_normalized_rule_bytes});
            }
            measured.raw_bytes += rule.size();

            auto normalized = protocol::DomainName::from_text(rule);
            if (!normalized)
                continue; // The authoritative builder reports the exact rule error.
            const size_t bytes = normalized->canonical_key().size();
            if (bytes > limits.maximum_normalized_rule_bytes - std::min(measured.normalized_bytes, limits.maximum_normalized_rule_bytes))
            {
                return std::unexpected(FilterUpdateError{FilterUpdateErrorCode::RuleBytesLimitExceeded, std::nullopt,
                                                         saturated_add(measured.normalized_bytes, bytes), limits.maximum_normalized_rule_bytes});
            }
            measured.normalized_bytes += bytes;
        }
        return measured;
    }
    catch (...)
    {
        return std::unexpected(FilterUpdateError{FilterUpdateErrorCode::InternalError, std::nullopt, 0, 0});
    }
}

FilterUpdateController::FilterUpdateController(FilterPublicationState &publication, Builder builder, FilterUpdateLimits limits)
    : publication_(publication)
    , builder_(std::move(builder))
    , limits_(limits)
{
    if (publication_.current_generation() == 0 || limits_.maximum_rule_count == 0 || limits_.maximum_normalized_rule_bytes == 0 ||
        limits_.maximum_queued_rule_bytes == 0)
        throw std::invalid_argument{"filter update controller requires a publication state and non-zero limits"};

    if (!builder_)
    {
        builder_ = [](std::span<const std::string> rules, FilterGeneration generation, std::stop_token stop_token)
        { return build_filter_snapshot(rules, generation, stop_token); };
    }
}

FilterUpdateController::~FilterUpdateController()
{
    close();
    std::unique_lock lock{mutex_};
    runner_stopped_.wait(lock, [this] { return !runner_active_; });
}

FilterUpdateFuture FilterUpdateController::submit_replace(std::vector<std::string> rules)
{
    auto measured = validate_filter_rule_set(rules, limits_);
    if (!measured)
        return ready_error(measured.error());

    std::unique_ptr<Command> command;
    try
    {
        command = std::make_unique<Command>(std::move(rules), measured->raw_bytes);
    }
    catch (...)
    {
        return ready_error(FilterUpdateError{FilterUpdateErrorCode::InternalError, std::nullopt, 0, 0});
    }
    auto future = command->completion.get_future();

    FilterUpdateError rejection;
    {
        std::scoped_lock lock{mutex_};
        if (sealed_)
        {
            rejection.code = FilterUpdateErrorCode::ShuttingDown;
        }
        else if (pending_.size() >= kMaximumPendingUpdates)
        {
            rejection.code   = FilterUpdateErrorCode::QueueFull;
            rejection.actual = pending_.size() + 1;
            rejection.limit  = kMaximumPendingUpdates;
        }
        else if (command->accounted_bytes > limits_.maximum_queued_rule_bytes - std::min(queued_rule_bytes_, limits_.maximum_queued_rule_bytes))
        {
            rejection.code   = FilterUpdateErrorCode::QueueBytesLimitExceeded;
            rejection.actual = saturated_add(queued_rule_bytes_, command->accounted_bytes);
            rejection.limit  = limits_.maximum_queued_rule_bytes;
        }
        else
        {
            try
            {
                const size_t accounted_bytes = command->accounted_bytes;
                pending_.push_back(std::move(command));
                queued_rule_bytes_ += accounted_bytes;
                wakeup_.notify_one();
                return future;
            }
            catch (...)
            {
                rejection.code = FilterUpdateErrorCode::InternalError;
            }
        }
    }

    complete(*command, std::unexpected(std::move(rejection)));
    return future;
}

FilterRunnerResult FilterUpdateController::run(std::stop_token stop_token, FilterRunnerObserver *observer) noexcept
{
    FilterRunnerResult result{};
    {
        std::scoped_lock lock{mutex_};
        if (runner_active_)
        {
            if (observer != nullptr)
                observer->report_ready(FilterRunnerReadyResult{FilterRunnerReadyCode::AlreadyRunning});
            return FilterRunnerResult{FilterRunnerExitCode::FatalExit};
        }
        runner_active_ = true;
    }

    if (observer != nullptr)
        observer->report_ready(FilterRunnerReadyResult{FilterRunnerReadyCode::Ready});

    try
    {
        std::stop_callback forward_stop{stop_token, [this] { request_terminal_detach(); }};
        const auto         build_stop_token = build_stop_source_.get_token();

        while (true)
        {
            bool detach_terminal{false};
            {
                std::unique_lock lock{mutex_};
                wakeup_.wait(lock, [this] { return terminal_detach_requested_ || !pending_.empty(); });
                if (!pending_.empty())
                {
                    inflight_ = std::move(pending_.front());
                    pending_.pop_front();
                    queued_rule_bytes_ -= std::min(queued_rule_bytes_, inflight_->accounted_bytes);
                    inflight_->phase = CommandPhase::Building;
                }
                else
                {
                    detach_terminal = terminal_detach_requested_;
                }
            }

            if (detach_terminal)
            {
                if (!publication_.detach_terminal_snapshot())
                    result.code = FilterRunnerExitCode::FatalExit;
                break;
            }

            FilterUpdateResult command_result = apply(*inflight_, build_stop_token);
            if (!command_result && inflight_->phase == CommandPhase::Committed)
            {
                // Publication is irreversible. Preserve the stable command
                // journal so a teardown successor can complete it as success
                // after the exact cohort converges.
                result.code = FilterRunnerExitCode::FatalExit;
                break;
            }
            complete(*inflight_, std::move(command_result));
            {
                std::scoped_lock lock{mutex_};
                inflight_->phase = CommandPhase::Completed;
                inflight_.reset();
            }
        }
    }
    catch (...)
    {
        result.code = FilterRunnerExitCode::FatalExit;
    }

    finish_run();
    return result;
}

void FilterUpdateController::seal() noexcept
{
    build_stop_source_.request_stop();
    publication_.seal_publication();

    std::deque<std::unique_ptr<Command>> cancelled;
    {
        std::scoped_lock lock{mutex_};
        if (!sealed_)
        {
            sealed_ = true;
            cancelled.swap(pending_);
            queued_rule_bytes_ = 0;
        }
        sealed_acknowledged_ = true;
    }

    wakeup_.notify_all();
    runner_stopped_.notify_all();
    for (auto &command : cancelled)
        complete(*command, update_error(FilterUpdateErrorCode::ShuttingDown));
}

void FilterUpdateController::request_terminal_detach() noexcept
{
    seal();
    {
        std::scoped_lock lock{mutex_};
        terminal_detach_requested_ = true;
    }
    wakeup_.notify_all();
}

bool FilterUpdateController::wait_until_sealed(std::stop_token stop_token) noexcept
{
    try
    {
        std::unique_lock lock{mutex_};
        return wakeup_.wait(lock, stop_token, [this] { return sealed_acknowledged_; });
    }
    catch (...)
    {
        return false;
    }
}

FilterSuccessorCompletionResult FilterUpdateController::complete_committed_by_successor() noexcept
{
    std::unique_ptr<Command>     completed;
    std::optional<FilterVersion> published;
    {
        std::scoped_lock lock{mutex_};
        if (runner_active_)
            return FilterSuccessorCompletionResult::WriterStillRunning;

        reconcile_inflight_after_writer_exit();
        if (!inflight_)
            return FilterSuccessorCompletionResult::Completed;

        if (inflight_->phase == CommandPhase::Committed && inflight_->published)
            published = inflight_->published;
        else
            completed = std::move(inflight_);
    }

    if (completed)
    {
        completed->phase = CommandPhase::Completed;
        complete(*completed, update_error(FilterUpdateErrorCode::InternalError));
        return FilterSuccessorCompletionResult::Completed;
    }

    const FilterGenerationWaitResult wait_result = publication_.wait_until_converged(published->generation);
    if (wait_result == FilterGenerationWaitResult::ReclaimerUnavailable)
        return FilterSuccessorCompletionResult::ReclaimerUnavailable;
    if (wait_result != FilterGenerationWaitResult::Converged)
        return FilterSuccessorCompletionResult::InternalError;

    {
        std::scoped_lock lock{mutex_};
        if (!inflight_)
            return FilterSuccessorCompletionResult::Completed;
        if (inflight_->phase != CommandPhase::Committed || inflight_->published != published)
            return FilterSuccessorCompletionResult::InternalError;
        inflight_->phase = CommandPhase::Completed;
        completed        = std::move(inflight_);
    }
    complete(*completed, *published);
    return FilterSuccessorCompletionResult::Completed;
}

FilterUpdateResult FilterUpdateController::apply(Command &command, std::stop_token stop_token) noexcept
{
    bool       credit_held{false};
    const auto release_credit = [this, &credit_held]() noexcept
    {
        if (credit_held)
        {
            publication_.release_uncommitted_credit();
            credit_held = false;
        }
    };

    try
    {
        if (stop_token.stop_requested())
            return update_error(FilterUpdateErrorCode::ShuttingDown);

        const FilterVersion current = publication_.current_version();
        if (current.generation == std::numeric_limits<FilterGeneration>::max())
            return update_error(FilterUpdateErrorCode::GenerationExhausted);

        if (!publication_.acquire_retirement_credit(stop_token))
            return update_error(FilterUpdateErrorCode::ShuttingDown);
        credit_held = true;

        const FilterGeneration next_generation = current.generation + 1;
        auto                   candidate       = builder_(command.rules, next_generation, stop_token);
        if (!candidate)
        {
            release_credit();
            if (stop_token.stop_requested() || candidate.error().code == Filter::BlocklistBuildErrorCode::Cancelled)
                return update_error(FilterUpdateErrorCode::ShuttingDown);
            return update_error(FilterUpdateErrorCode::BuildFailed, candidate.error());
        }
        if (!*candidate || (*candidate)->generation != next_generation)
        {
            release_credit();
            return update_error(FilterUpdateErrorCode::InternalError);
        }
        if (stop_token.stop_requested())
        {
            release_credit();
            return update_error(FilterUpdateErrorCode::ShuttingDown);
        }

        command.target = FilterVersion{(*candidate)->generation, (*candidate)->blocklist.rule_count()};
        command.phase  = CommandPhase::Publishing;
        auto committed = publication_.commit(std::move(*candidate));
        if (!committed)
        {
            command.phase = CommandPhase::Building;
            command.target.reset();
            release_credit();
            return update_error(committed.error() == FilterCommitError::PublicationSealed ? FilterUpdateErrorCode::ShuttingDown
                                                                                          : FilterUpdateErrorCode::InternalError);
        }

        credit_held       = false; // B now owns the credit and retired owner.
        command.phase     = CommandPhase::Committed;
        command.published = *committed;
        if (fail_after_commit_for_testing_.exchange(false, std::memory_order_acq_rel))
            throw InjectedPostcommitFailure{};
        if (publication_.wait_until_converged(committed->generation) != FilterGenerationWaitResult::Converged)
            return update_error(FilterUpdateErrorCode::InternalError);
        return *committed;
    }
    catch (...)
    {
        release_credit();
        return update_error(stop_token.stop_requested() ? FilterUpdateErrorCode::ShuttingDown : FilterUpdateErrorCode::InternalError);
    }
}

void FilterUpdateController::complete(Command &command, FilterUpdateResult result) noexcept
{
    try
    {
        command.completion.set_value(std::move(result));
    }
    catch (...)
    {
    }
}

void FilterUpdateController::cancel_pending(FilterUpdateErrorCode code) noexcept
{
    std::deque<std::unique_ptr<Command>> cancelled;
    {
        std::scoped_lock lock{mutex_};
        cancelled.swap(pending_);
        queued_rule_bytes_ = 0;
    }
    for (auto &command : cancelled)
        complete(*command, update_error(code));
}

void FilterUpdateController::finish_run() noexcept
{
    seal();
    cancel_pending(FilterUpdateErrorCode::ShuttingDown);

    {
        std::scoped_lock lock{mutex_};
        reconcile_inflight_after_writer_exit();
        if (inflight_ && inflight_->phase != CommandPhase::Committed)
        {
            complete(*inflight_, update_error(FilterUpdateErrorCode::InternalError));
            inflight_.reset();
        }
        runner_active_ = false;
    }
    runner_stopped_.notify_all();
    wakeup_.notify_all();
}

void FilterUpdateController::reconcile_inflight_after_writer_exit() noexcept
{
    if (!inflight_ || inflight_->phase != CommandPhase::Publishing || !inflight_->target)
        return;

    const FilterVersion current = publication_.current_version();
    if (current == *inflight_->target)
    {
        inflight_->phase     = CommandPhase::Committed;
        inflight_->published = inflight_->target;
    }
    else
    {
        inflight_->phase = CommandPhase::Building;
        inflight_->target.reset();
    }
}

void FilterUpdateController::inject_postcommit_failure_for_testing() noexcept
{
    fail_after_commit_for_testing_.store(true, std::memory_order_release);
}

} // namespace dns::server
