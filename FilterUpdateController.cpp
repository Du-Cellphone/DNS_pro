#include "FilterUpdateController.h"

#include <limits>
#include <stdexcept>
#include <utility>

namespace dns::server
{
namespace
{

FilterUpdateResult update_error(FilterUpdateErrorCode code, std::optional<Filter::BlocklistBuildError> build_error = std::nullopt)
{
    return std::unexpected(FilterUpdateError{code, std::move(build_error)});
}

} // namespace

FilterUpdateController::FilterUpdateController(FilterSnapshot initial_snapshot, Builder builder)
    : builder_(std::move(builder))
{
    if (!initial_snapshot || initial_snapshot->generation == 0)
        throw std::invalid_argument{"filter update controller requires a non-zero initial snapshot"};

    if (!builder_)
    {
        builder_ = [](std::span<const std::string> rules, FilterGeneration generation, std::stop_token stop_token)
        { return build_filter_snapshot(rules, generation, stop_token); };
    }
    active_snapshot_.store(std::move(initial_snapshot), std::memory_order_release);
}

FilterUpdateController::~FilterUpdateController()
{
    close();
    std::unique_lock lock{mutex_};
    runner_stopped_.wait(lock, [this] { return !runner_active_; });
}

FilterUpdateFuture FilterUpdateController::submit_replace(std::vector<std::string> rules)
{
    auto command = std::make_unique<Command>(std::move(rules));
    auto future  = command->completion.get_future();

    FilterUpdateErrorCode rejection = FilterUpdateErrorCode::InternalError;
    {
        std::scoped_lock lock{mutex_};
        if (closed_)
        {
            rejection = FilterUpdateErrorCode::ShuttingDown;
        }
        else if (pending_.size() >= kMaximumPendingUpdates)
        {
            rejection = FilterUpdateErrorCode::QueueFull;
        }
        else
        {
            pending_.push_back(std::move(command));
            wakeup_.notify_one();
            return future;
        }
    }

    complete(*command, update_error(rejection));
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
        std::stop_callback    forward_stop{stop_token, [this]
                                        {
                                            build_stop_source_.request_stop();
                                            wakeup_.notify_all();
                                        }};
        const std::stop_token build_stop_token = build_stop_source_.get_token();

        while (!stop_token.stop_requested())
        {
            std::unique_ptr<Command> command;
            {
                std::unique_lock lock{mutex_};
                wakeup_.wait(lock, stop_token, [this] { return closed_ || !pending_.empty(); });
                if (stop_token.stop_requested() || closed_)
                    break;

                command = std::move(pending_.front());
                pending_.pop_front();
            }

            complete(*command, apply(command->rules, build_stop_token));
        }
    }
    catch (...)
    {
        result.code = FilterRunnerExitCode::FatalExit;
    }

    finish_run();
    return result;
}

void FilterUpdateController::close() noexcept
{
    build_stop_source_.request_stop();

    std::deque<std::unique_ptr<Command>> cancelled;
    {
        std::scoped_lock lock{mutex_};
        if (closed_)
            return;
        closed_ = true;
        cancelled.swap(pending_);
    }

    wakeup_.notify_all();
    for (auto &command : cancelled)
        complete(*command, update_error(FilterUpdateErrorCode::ShuttingDown));
}

FilterSnapshot FilterUpdateController::snapshot() const noexcept
{
    return active_snapshot_.load(std::memory_order_acquire);
}

std::optional<FilterVersion> FilterUpdateController::current_version() const noexcept
{
    const FilterSnapshot current = snapshot();
    if (!current)
        return std::nullopt;
    return FilterVersion{current->generation, current->blocklist.rule_count()};
}

FilterUpdateResult FilterUpdateController::apply(std::span<const std::string> rules, std::stop_token stop_token) noexcept
{
    try
    {
        if (stop_token.stop_requested())
            return update_error(FilterUpdateErrorCode::ShuttingDown);

        const FilterSnapshot current = snapshot();
        if (!current)
            return update_error(FilterUpdateErrorCode::InternalError);
        if (current->generation == std::numeric_limits<FilterGeneration>::max())
        {
            if (stop_token.stop_requested())
                return update_error(FilterUpdateErrorCode::ShuttingDown);
            return update_error(FilterUpdateErrorCode::GenerationExhausted);
        }

        const FilterGeneration next_generation = current->generation + 1;
        auto                   candidate       = builder_(rules, next_generation, stop_token);
        if (!candidate)
        {
            if (stop_token.stop_requested() || candidate.error().code == Filter::BlocklistBuildErrorCode::Cancelled)
                return update_error(FilterUpdateErrorCode::ShuttingDown);
            return update_error(FilterUpdateErrorCode::BuildFailed, candidate.error());
        }
        if (!*candidate || (*candidate)->generation != next_generation)
            return update_error(FilterUpdateErrorCode::InternalError);

        FilterSnapshot retired;
        FilterVersion  published;
        {
            std::scoped_lock lock{mutex_};
            if (closed_ || stop_token.stop_requested())
                return update_error(FilterUpdateErrorCode::ShuttingDown);

            const FilterSnapshot latest = active_snapshot_.load(std::memory_order_acquire);
            if (latest != current)
                return update_error(FilterUpdateErrorCode::InternalError);

            published = FilterVersion{(*candidate)->generation, (*candidate)->blocklist.rule_count()};
            retired   = active_snapshot_.exchange(std::move(*candidate), std::memory_order_acq_rel);
        }
        return published;
    }
    catch (...)
    {
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

void FilterUpdateController::finish_run() noexcept
{
    std::deque<std::unique_ptr<Command>> cancelled;
    {
        std::scoped_lock lock{mutex_};
        closed_ = true;
        cancelled.swap(pending_);
    }
    for (auto &command : cancelled)
        complete(*command, update_error(FilterUpdateErrorCode::ShuttingDown));

    {
        std::scoped_lock lock{mutex_};
        runner_active_ = false;
        runner_stopped_.notify_all();
    }
}

} // namespace dns::server
