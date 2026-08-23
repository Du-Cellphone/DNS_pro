#include "FilterPublication.h"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <utility>

namespace dns::server
{

FilterPublicationState::FilterPublicationState(FilterSnapshot initial_snapshot, Config config)
    : config_(config)
    , registry_(config.maximum_workers, nullptr)
    , retired_(config.maximum_workers)
    , terminal_(config.maximum_workers)
{
    if (!initial_snapshot || initial_snapshot->generation == 0 || config_.grace_timeout <= std::chrono::milliseconds::zero())
        throw std::invalid_argument{"filter publication state requires a valid initial snapshot and grace timeout"};

    current_generation_.store(initial_snapshot->generation, std::memory_order_relaxed);
    current_rule_count_.store(initial_snapshot->blocklist.rule_count(), std::memory_order_relaxed);
    current_normalized_rule_bytes_.store(initial_snapshot->normalized_rule_bytes, std::memory_order_relaxed);
    active_snapshot_.store(std::move(initial_snapshot), std::memory_order_release);
}

FilterPublicationState::~FilterPublicationState()
{
    // Letting the state die while a worker or B can still touch it would turn
    // a recoverable teardown failure into a use-after-free. DNS treats this as
    // a fail-fast invariant; initialization-only/static-snapshot paths have no
    // registered participants or pending retirement records.
    {
        std::scoped_lock retirement_lock{retirement_mutex_};
        std::scoped_lock publication_lock{publication_mutex_};
        if (reclaimer_active_ || retired_.pending || retired_.destroying || terminal_.pending || terminal_.destroying ||
            std::ranges::any_of(registry_, [](const WorkerEpoch *epoch) { return epoch != nullptr; }))
            std::terminate();
    }
    active_snapshot_.store(nullptr, std::memory_order_release);
}

void FilterPublicationState::set_publication_sink(FilterPublicationSink *sink) noexcept
{
    std::scoped_lock lock{publication_mutex_};
    publication_sink_ = sink;
}

std::optional<FilterWorkerRegistration> FilterPublicationState::register_worker(size_t worker_id, uint64_t instance_id, WorkerEpoch &epoch) noexcept
{
    try
    {
        std::scoped_lock lock{publication_mutex_};
        if (worker_id >= registry_.size() || instance_id == 0 || registry_[worker_id] != nullptr ||
            publication_sealed_.load(std::memory_order_acquire))
            return std::nullopt;

        FilterSnapshot snapshot = active_snapshot_.load(std::memory_order_acquire);
        if (!snapshot)
            return std::nullopt;

        epoch.observed_generation.store(kUnobservedFilterGeneration, std::memory_order_relaxed);
        epoch.registration_state.store(WorkerRegistrationState::Starting, std::memory_order_relaxed);
        epoch.published_instance_id.store(instance_id, std::memory_order_release);
        registry_[worker_id] = &epoch;
        return FilterWorkerRegistration{std::move(snapshot), current_generation_.load(std::memory_order_relaxed)};
    }
    catch (...)
    {
        return std::nullopt;
    }
}

bool FilterPublicationState::mark_worker_registered(size_t worker_id, uint64_t instance_id, WorkerEpoch &epoch) noexcept
{
    std::scoped_lock lock{publication_mutex_};
    if (worker_id >= registry_.size() || registry_[worker_id] != &epoch ||
        epoch.published_instance_id.load(std::memory_order_acquire) != instance_id ||
        epoch.registration_state.load(std::memory_order_acquire) != WorkerRegistrationState::Starting)
        return false;

    const uint64_t         first      = epoch.published_instance_id.load(std::memory_order_acquire);
    const FilterGeneration observed   = epoch.observed_generation.load(std::memory_order_acquire);
    const uint64_t         second     = epoch.published_instance_id.load(std::memory_order_acquire);
    const FilterGeneration generation = current_generation_.load(std::memory_order_relaxed);
    if (first != instance_id || second != instance_id || observed < generation)
        return false;

    epoch.registration_state.store(WorkerRegistrationState::Registered, std::memory_order_release);
    return true;
}

void FilterPublicationState::quiesce_worker(size_t worker_id, uint64_t instance_id, WorkerEpoch &epoch) noexcept
{
    {
        std::scoped_lock lock{publication_mutex_};
        if (worker_id < registry_.size() && registry_[worker_id] == &epoch &&
            epoch.published_instance_id.load(std::memory_order_acquire) == instance_id)
        {
            epoch.quiesced_through_instance_id.store(instance_id, std::memory_order_release);
            epoch.registration_state.store(WorkerRegistrationState::Unregistered, std::memory_order_release);
            registry_[worker_id] = nullptr;
        }
    }
    publish_progress();
}

bool FilterPublicationState::refresh_worker_snapshot(FilterSnapshot &local_snapshot, uint64_t instance_id, WorkerEpoch &epoch) noexcept
{
    bool advanced{false};
    {
        std::scoped_lock lock{publication_mutex_};
        if (epoch.published_instance_id.load(std::memory_order_acquire) != instance_id ||
            epoch.registration_state.load(std::memory_order_acquire) == WorkerRegistrationState::Unregistered)
            return false;

        FilterSnapshot next = active_snapshot_.load(std::memory_order_acquire);
        if (!next || !local_snapshot)
            return false;

        const FilterGeneration observed = epoch.observed_generation.load(std::memory_order_relaxed);
        if (local_snapshot->generation > next->generation || observed > local_snapshot->generation)
            return false;
        if (local_snapshot != next)
        {
            FilterSnapshot old = std::exchange(local_snapshot, std::move(next));
            old.reset();
        }
        if (observed < local_snapshot->generation)
        {
            // local_snapshot now owns the new tree and the previous local owner
            // has been released. Only then may B accept this generation ack.
            epoch.observed_generation.store(local_snapshot->generation, std::memory_order_release);
            advanced = true;
        }
    }
    if (advanced)
        publish_progress();
    return true;
}

bool FilterPublicationState::worker_needs_refresh(uint64_t instance_id, const WorkerEpoch &epoch) const noexcept
{
    const uint64_t         first    = epoch.published_instance_id.load(std::memory_order_acquire);
    const FilterGeneration observed = epoch.observed_generation.load(std::memory_order_acquire);
    const uint64_t         second   = epoch.published_instance_id.load(std::memory_order_acquire);
    return first == instance_id && second == instance_id && observed < current_generation_.load(std::memory_order_acquire);
}

bool FilterPublicationState::acquire_retirement_credit(std::stop_token stop_token) noexcept
{
    try
    {
        std::unique_lock lock{retirement_mutex_};
        const bool       ready = retirement_changed_.wait(lock, stop_token, [this]
                                                          { return !retirement_credit_held_ || publication_sealed_.load(std::memory_order_acquire); });
        if (!ready || publication_sealed_.load(std::memory_order_acquire) || stop_token.stop_requested())
            return false;
        retirement_credit_held_ = true;
        return true;
    }
    catch (...)
    {
        return false;
    }
}

void FilterPublicationState::release_uncommitted_credit() noexcept
{
    {
        std::scoped_lock lock{retirement_mutex_};
        if (!retired_.pending)
            retirement_credit_held_ = false;
    }
    retirement_changed_.notify_all();
}

FilterCommitResult FilterPublicationState::commit(FilterSnapshot candidate) noexcept
{
    FilterPublicationSink *sink{nullptr};
    FilterVersion          published;
    {
        std::scoped_lock retirement_lock{retirement_mutex_};
        if (!retirement_credit_held_ || retired_.pending)
            return std::unexpected(FilterCommitError::NoRetirementCredit);

        std::scoped_lock publication_lock{publication_mutex_};
        if (publication_sealed_.load(std::memory_order_relaxed))
            return std::unexpected(FilterCommitError::PublicationSealed);
        if (!candidate || candidate->generation == 0)
            return std::unexpected(FilterCommitError::InvalidCandidate);

        const FilterGeneration current = current_generation_.load(std::memory_order_relaxed);
        if (current == std::numeric_limits<FilterGeneration>::max() || candidate->generation != current + 1)
            return std::unexpected(FilterCommitError::GenerationMismatch);

        retired_.cohort.clear();
        for (size_t worker_id = 0; worker_id < registry_.size(); ++worker_id)
        {
            WorkerEpoch *epoch = registry_[worker_id];
            if (epoch == nullptr)
                continue;
            const WorkerRegistrationState registration = epoch->registration_state.load(std::memory_order_acquire);
            const uint64_t                instance_id  = epoch->published_instance_id.load(std::memory_order_acquire);
            if (instance_id != 0 && (registration == WorkerRegistrationState::Starting || registration == WorkerRegistrationState::Registered))
                retired_.cohort.push_back(CohortMember{worker_id, instance_id, epoch});
        }

        published                                = FilterVersion{candidate->generation, candidate->blocklist.rule_count()};
        retired_.version                         = published;
        retired_.published_normalized_rule_bytes = candidate->normalized_rule_bytes;
        retired_.retired_bytes                   = current_normalized_rule_bytes_.load(std::memory_order_relaxed);
        retired_.committed_at                    = std::chrono::steady_clock::now();
        retired_.destroying                      = false;
        retired_.terminal                        = false;

        // COMMIT. All storage used below was reserved at construction and all
        // remaining operations are non-allocating moves/stores.
        retired_.owner   = active_snapshot_.exchange(std::move(candidate), std::memory_order_acq_rel);
        retired_.pending = true;
        retired_bytes_   = retired_.retired_bytes;
        current_generation_.store(published.generation, std::memory_order_release);
        current_rule_count_.store(published.rule_count, std::memory_order_release);
        current_normalized_rule_bytes_.store(retired_.published_normalized_rule_bytes, std::memory_order_release);
        sink = publication_sink_;
    }

    retirement_changed_.notify_all();
    if (sink != nullptr)
        sink->snapshot_published(published.generation);
    return published;
}

FilterGenerationWaitResult FilterPublicationState::wait_until_reclaimed(FilterGeneration generation) noexcept
{
    try
    {
        std::unique_lock lock{retirement_mutex_};
        retirement_changed_.wait(lock, [this, generation]
                                 { return last_reclaimed_generation_ >= generation || (reclaimer_started_ && !reclaimer_active_); });
        return last_reclaimed_generation_ >= generation ? FilterGenerationWaitResult::Converged : FilterGenerationWaitResult::ReclaimerUnavailable;
    }
    catch (...)
    {
        return FilterGenerationWaitResult::InternalError;
    }
}

FilterGenerationWaitResult FilterPublicationState::wait_until_converged(FilterGeneration generation) noexcept
{
    try
    {
        std::unique_lock lock{retirement_mutex_};
        retirement_changed_.wait(lock, [this, generation]
                                 { return last_converged_generation_ >= generation || (reclaimer_started_ && !reclaimer_active_); });
        return last_converged_generation_ >= generation ? FilterGenerationWaitResult::Converged : FilterGenerationWaitResult::ReclaimerUnavailable;
    }
    catch (...)
    {
        return FilterGenerationWaitResult::InternalError;
    }
}

void FilterPublicationState::seal_publication() noexcept
{
    {
        // Keep the same retirement -> publication order as commit/detach. The
        // retirement mutex closes acquire_retirement_credit's predicate/wait
        // window, so this notification cannot be lost.
        std::scoped_lock retirement_lock{retirement_mutex_};
        std::scoped_lock publication_lock{publication_mutex_};
        publication_sealed_.store(true, std::memory_order_release);
    }
    retirement_changed_.notify_all();
}

bool FilterPublicationState::detach_terminal_snapshot() noexcept
{
    {
        std::scoped_lock retirement_lock{retirement_mutex_};
        std::scoped_lock publication_lock{publication_mutex_};
        if (terminal_.pending)
            return true;

        FilterSnapshot active = active_snapshot_.load(std::memory_order_acquire);
        if (!active)
            return true;

        terminal_.cohort.clear();
        for (size_t worker_id = 0; worker_id < registry_.size(); ++worker_id)
        {
            WorkerEpoch *epoch = registry_[worker_id];
            if (epoch == nullptr)
                continue;
            const WorkerRegistrationState registration = epoch->registration_state.load(std::memory_order_acquire);
            const uint64_t                instance_id  = epoch->published_instance_id.load(std::memory_order_acquire);
            if (instance_id != 0 && (registration == WorkerRegistrationState::Starting || registration == WorkerRegistrationState::Registered))
                terminal_.cohort.push_back(CohortMember{worker_id, instance_id, epoch});
        }

        terminal_.version                         = FilterVersion{active->generation, active->blocklist.rule_count()};
        terminal_.published_normalized_rule_bytes = active->normalized_rule_bytes;
        terminal_.retired_bytes                   = active->normalized_rule_bytes;
        terminal_.committed_at                    = std::chrono::steady_clock::now();
        terminal_.destroying                      = false;
        terminal_.terminal                        = true;
        terminal_.owner                           = active_snapshot_.exchange(nullptr, std::memory_order_acq_rel);
        terminal_.pending                         = true;
        retired_bytes_ = terminal_.retired_bytes > std::numeric_limits<size_t>::max() - retired_bytes_ ? std::numeric_limits<size_t>::max()
                                                                                                       : retired_bytes_ + terminal_.retired_bytes;
    }
    retirement_changed_.notify_all();
    return true;
}

SnapshotReclaimerResult FilterPublicationState::run_reclaimer(std::stop_token stop_token, SnapshotReclaimerObserver *observer) noexcept
{
    {
        std::scoped_lock lock{retirement_mutex_};
        if (reclaimer_active_)
        {
            if (observer != nullptr)
                observer->report_reclaimer_ready(SnapshotReclaimerReadyResult{SnapshotReclaimerReadyCode::AlreadyRunning});
            return SnapshotReclaimerResult{SnapshotReclaimerExitCode::FatalExit, nullptr};
        }
        reclaimer_started_ = true;
        reclaimer_active_  = true;
    }
    if (observer != nullptr)
        observer->report_reclaimer_ready(SnapshotReclaimerReadyResult{SnapshotReclaimerReadyCode::Ready});

    SnapshotReclaimerResult result;
    try
    {
        std::stop_callback wake_on_stop{stop_token, [this]
                                        {
                                            {
                                                std::scoped_lock lock{retirement_mutex_};
                                                progress_sequence_.fetch_add(1, std::memory_order_release);
                                            }
                                            retirement_changed_.notify_all();
                                        }};
        std::unique_lock   lock{retirement_mutex_};
        while (true)
        {
            if (reclaimer_failure_requested_)
            {
                result.code = SnapshotReclaimerExitCode::FatalExit;
                break;
            }
            if (reclaimer_failure_after_commit_requested_ && retired_.pending)
            {
                reclaimer_failure_after_commit_requested_ = false;
                result.code                               = SnapshotReclaimerExitCode::FatalExit;
                break;
            }

            if (RetirementRecord *record = next_pending_record_locked(); record != nullptr)
            {
                if (cohort_complete(*record))
                {
                    const bool returns_credit = record == &retired_;
                    if (record->owner && record->owner.use_count() != 1)
                    {
                        // The exact cohort has released its owners. Any extra
                        // owner is outside the protocol, so resetting the
                        // stable record could move final destruction to an
                        // arbitrary thread.
                        result.code = SnapshotReclaimerExitCode::FatalExit;
                        break;
                    }

                    const FilterGeneration generation    = record->version.generation;
                    const size_t           retired_bytes = record->retired_bytes;
                    record->destroying                   = true;
                    if (returns_credit)
                        last_converged_generation_ = std::max(last_converged_generation_, generation);
                    FilterSnapshot sole_owner = std::move(record->owner);

                    // Publish convergence before doing potentially expensive
                    // destruction. A may complete the committed future now,
                    // while the one retirement credit remains held until B
                    // has finished the destructor.
                    lock.unlock();
                    retirement_changed_.notify_all();
                    sole_owner.reset(); // Normal path: destruction is on B.
                    lock.lock();

                    retired_bytes_ -= std::min(retired_bytes_, retired_bytes);
                    record->cohort.clear();
                    record->pending                         = false;
                    record->destroying                      = false;
                    record->terminal                        = false;
                    record->retired_bytes                   = 0;
                    record->version                         = {};
                    record->published_normalized_rule_bytes = 0;
                    if (returns_credit)
                    {
                        retirement_credit_held_    = false;
                        last_reclaimed_generation_ = std::max(last_reclaimed_generation_, generation);
                    }
                    retirement_changed_.notify_all();
                    continue;
                }

                const auto now      = std::chrono::steady_clock::now();
                const auto deadline = record->committed_at + config_.grace_timeout;
                if (now >= deadline)
                {
                    result.code       = SnapshotReclaimerExitCode::GracePeriodStalled;
                    result.diagnostic = std::make_shared<FilterGraceDiagnostic>(make_diagnostic(*record, now));
                    break;
                }

                const uint64_t observed_sequence = progress_sequence_.load(std::memory_order_acquire);
                retirement_changed_.wait_until(
                    lock, deadline, [this, observed_sequence]
                    { return reclaimer_failure_requested_ || progress_sequence_.load(std::memory_order_acquire) != observed_sequence; });
                continue;
            }

            if (reclaimer_shutdown_requested_ || stop_token.stop_requested())
            {
                result.code = SnapshotReclaimerExitCode::RequestedStop;
                break;
            }
            retirement_changed_.wait(lock);
        }
    }
    catch (...)
    {
        result.code = SnapshotReclaimerExitCode::FatalExit;
        result.diagnostic.reset();
    }

    {
        std::scoped_lock lock{retirement_mutex_};
        reclaimer_active_ = false;
    }
    retirement_changed_.notify_all();
    return result;
}

void FilterPublicationState::request_reclaimer_shutdown() noexcept
{
    {
        std::scoped_lock lock{retirement_mutex_};
        reclaimer_shutdown_requested_ = true;
    }
    retirement_changed_.notify_all();
}

void FilterPublicationState::inject_reclaimer_failure_for_testing() noexcept
{
    {
        std::scoped_lock lock{retirement_mutex_};
        reclaimer_failure_requested_ = true;
    }
    retirement_changed_.notify_all();
}

void FilterPublicationState::inject_reclaimer_failure_after_next_commit_for_testing() noexcept
{
    {
        std::scoped_lock lock{retirement_mutex_};
        reclaimer_failure_after_commit_requested_ = true;
    }
    retirement_changed_.notify_all();
}

bool FilterPublicationState::emergency_reclaim_converged() noexcept
{
    std::scoped_lock lock{retirement_mutex_};
    if (reclaimer_active_ || !publication_sealed_.load(std::memory_order_acquire))
        return false;
    return reclaim_converged_locked();
}

FilterVersion FilterPublicationState::current_version() const noexcept
{
    // These fields are published together while holding publication_mutex_.
    // Locking this low-frequency metadata read prevents a torn pair while
    // retaining the last version after the terminal active slot is detached.
    std::scoped_lock lock{publication_mutex_};
    return FilterVersion{current_generation_.load(std::memory_order_relaxed), current_rule_count_.load(std::memory_order_relaxed)};
}

FilterGeneration FilterPublicationState::current_generation() const noexcept
{
    return current_generation_.load(std::memory_order_acquire);
}

FilterRetirementStats FilterPublicationState::retirement_stats() const noexcept
{
    std::scoped_lock lock{retirement_mutex_};
    return FilterRetirementStats{
        .unreclaimed_generations   = static_cast<size_t>(retired_.pending),
        .retired_bytes             = retired_bytes_,
        .progress_sequence         = progress_sequence_.load(std::memory_order_acquire),
        .last_converged_generation = last_converged_generation_,
        .last_reclaimed_generation = last_reclaimed_generation_,
        .retirement_credit_held    = retirement_credit_held_,
        .terminal_owner_pending    = terminal_.pending,
    };
}

bool FilterPublicationState::current_matches(std::string_view domain) const
{
    std::scoped_lock     lock{publication_mutex_};
    const FilterSnapshot current = active_snapshot_.load(std::memory_order_acquire);
    return current && current->blocklist.matches(domain);
}

bool FilterPublicationState::member_complete(const CohortMember &member, FilterGeneration generation, bool terminal) const noexcept
{
    if (member.epoch == nullptr)
        return false;

    const uint64_t quiesced = member.epoch->quiesced_through_instance_id.load(std::memory_order_acquire);
    if (quiesced >= member.instance_id)
        return true;
    if (terminal)
        return false;

    const uint64_t         first    = member.epoch->published_instance_id.load(std::memory_order_acquire);
    const FilterGeneration observed = member.epoch->observed_generation.load(std::memory_order_acquire);
    const uint64_t         second   = member.epoch->published_instance_id.load(std::memory_order_acquire);
    return first == member.instance_id && second == member.instance_id && observed >= generation;
}

bool FilterPublicationState::cohort_complete(const RetirementRecord &record) const noexcept
{
    for (const CohortMember &member : record.cohort)
    {
        if (!member_complete(member, record.version.generation, record.terminal))
            return false;
    }
    return true;
}

FilterGraceDiagnostic FilterPublicationState::make_diagnostic(const RetirementRecord &record, std::chrono::steady_clock::time_point now) const
{
    FilterGraceDiagnostic diagnostic;
    diagnostic.target_generation = record.version.generation;
    diagnostic.retired_bytes     = record.retired_bytes;
    diagnostic.waited            = std::chrono::duration_cast<std::chrono::milliseconds>(now - record.committed_at);
    diagnostic.pending.reserve(record.cohort.size());
    for (const CohortMember &member : record.cohort)
    {
        if (!member_complete(member, record.version.generation, record.terminal))
        {
            diagnostic.pending.push_back(PendingFilterParticipant{
                member.worker_id,
                member.instance_id,
                member.epoch != nullptr ? member.epoch->observed_generation.load(std::memory_order_acquire) : kUnobservedFilterGeneration,
            });
        }
    }
    return diagnostic;
}

void FilterPublicationState::publish_progress() noexcept
{
    {
        // Taking the same mutex used by B's wait closes the classic
        // predicate-check/wait lost-wakeup window. This runs once per
        // generation/quiescence, never once per request.
        std::scoped_lock lock{retirement_mutex_};
        progress_sequence_.fetch_add(1, std::memory_order_release);
    }
    retirement_changed_.notify_all();
}

void FilterPublicationState::reclaim_record(RetirementRecord &record, bool returns_credit) noexcept
{
    const FilterGeneration generation = record.version.generation;
    retired_bytes_ -= std::min(retired_bytes_, record.retired_bytes);
    record.owner.reset(); // Emergency path after B has been proven stopped.
    record.cohort.clear();
    record.pending                         = false;
    record.destroying                      = false;
    record.terminal                        = false;
    record.retired_bytes                   = 0;
    record.version                         = {};
    record.published_normalized_rule_bytes = 0;
    if (returns_credit)
    {
        retirement_credit_held_    = false;
        last_converged_generation_ = std::max(last_converged_generation_, generation);
        last_reclaimed_generation_ = std::max(last_reclaimed_generation_, generation);
    }
}

bool FilterPublicationState::reclaim_converged_locked() noexcept
{
    if (retired_.pending && !cohort_complete(retired_))
        return false;
    if (terminal_.pending && !cohort_complete(terminal_))
        return false;
    if ((retired_.owner && retired_.owner.use_count() != 1) || (terminal_.owner && terminal_.owner.use_count() != 1))
        return false;
    if (retired_.pending)
        reclaim_record(retired_, true);
    if (terminal_.pending)
        reclaim_record(terminal_, false);
    retirement_changed_.notify_all();
    return true;
}

FilterPublicationState::RetirementRecord *FilterPublicationState::next_pending_record_locked() noexcept
{
    if (retired_.pending)
        return &retired_;
    if (terminal_.pending)
        return &terminal_;
    return nullptr;
}

} // namespace dns::server
