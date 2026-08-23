#pragma once

#include "FilterContext.h"
#include "common/Expected.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string_view>
#include <vector>

namespace dns::server
{

inline constexpr FilterGeneration kUnobservedFilterGeneration = 0;

enum class WorkerRegistrationState : uint8_t
{
    Unregistered,
    Starting,
    Registered,
};

// This is the only part of a logical worker that the publication/reclamation
// protocol reads across threads. Its address remains stable for the lifetime
// of the WorkerRecord that owns it.
struct alignas(64) WorkerEpoch final
{
    std::atomic<uint64_t>                published_instance_id{0};
    std::atomic<FilterGeneration>        observed_generation{kUnobservedFilterGeneration};
    std::atomic<WorkerRegistrationState> registration_state{WorkerRegistrationState::Unregistered};
    std::atomic<uint64_t>                quiesced_through_instance_id{0};
};

static_assert(alignof(WorkerEpoch) >= 64);

struct FilterVersion final
{
    FilterGeneration generation{0};
    size_t           rule_count{0};

    bool operator==(const FilterVersion &) const = default;
};

struct FilterWorkerRegistration final
{
    FilterSnapshot   snapshot;
    FilterGeneration generation{0};
};

class FilterPublicationSink
{
public:
    virtual ~FilterPublicationSink()                                      = default;
    virtual void snapshot_published(FilterGeneration generation) noexcept = 0;
};

enum class FilterCommitError : uint8_t
{
    NoRetirementCredit,
    PublicationSealed,
    InvalidCandidate,
    GenerationMismatch,
};

using FilterCommitResult = std::expected<FilterVersion, FilterCommitError>;

enum class FilterGenerationWaitResult : uint8_t
{
    Converged,
    ReclaimerUnavailable,
    InternalError,
};

enum class SnapshotReclaimerReadyCode : uint8_t
{
    Ready,
    AlreadyRunning,
};

struct SnapshotReclaimerReadyResult final
{
    SnapshotReclaimerReadyCode code{SnapshotReclaimerReadyCode::Ready};
};

struct PendingFilterParticipant final
{
    size_t           worker_id{0};
    uint64_t         instance_id{0};
    FilterGeneration observed_generation{kUnobservedFilterGeneration};

    bool operator==(const PendingFilterParticipant &) const = default;
};

struct FilterGraceDiagnostic final
{
    FilterGeneration                      target_generation{0};
    size_t                                retired_bytes{0};
    std::chrono::milliseconds             waited{0};
    std::vector<PendingFilterParticipant> pending;

    bool operator==(const FilterGraceDiagnostic &) const = default;
};

enum class SnapshotReclaimerExitCode : uint8_t
{
    RequestedStop,
    GracePeriodStalled,
    FatalExit,
};

struct SnapshotReclaimerResult final
{
    SnapshotReclaimerExitCode                    code{SnapshotReclaimerExitCode::RequestedStop};
    std::shared_ptr<const FilterGraceDiagnostic> diagnostic;

    bool operator==(const SnapshotReclaimerResult &other) const
    {
        return code == other.code && static_cast<bool>(diagnostic) == static_cast<bool>(other.diagnostic) &&
               (!diagnostic || *diagnostic == *other.diagnostic);
    }
};

class SnapshotReclaimerObserver
{
public:
    virtual ~SnapshotReclaimerObserver()                                              = default;
    virtual void report_reclaimer_ready(SnapshotReclaimerReadyResult result) noexcept = 0;
};

struct FilterRetirementStats final
{
    size_t           unreclaimed_generations{0};
    size_t           retired_bytes{0};
    uint64_t         progress_sequence{0};
    FilterGeneration last_converged_generation{0};
    FilterGeneration last_reclaimed_generation{0};
    bool             retirement_credit_held{false};
    bool             terminal_owner_pending{false};

    bool operator==(const FilterRetirementStats &) const = default;
};

struct FilterPublicationTestPeer;

// DNS owns this object. A is its sole normal publisher, B is its sole normal
// reclaimer, C registers/quiesces participants, and workers only refresh their
// own local snapshot. No owner required for emergency takeover lives on a
// control thread's stack.
class FilterPublicationState final
{
public:
    struct Config final
    {
        size_t                    maximum_workers{0};
        std::chrono::milliseconds grace_timeout{std::chrono::seconds{30}};
    };

    FilterPublicationState(FilterSnapshot initial_snapshot, Config config);
    ~FilterPublicationState();

    FilterPublicationState(const FilterPublicationState &)            = delete;
    FilterPublicationState &operator=(const FilterPublicationState &) = delete;

    void set_publication_sink(FilterPublicationSink *sink) noexcept;

    [[nodiscard]] std::optional<FilterWorkerRegistration> register_worker(size_t worker_id, uint64_t instance_id, WorkerEpoch &epoch) noexcept;
    [[nodiscard]] bool                                    mark_worker_registered(size_t worker_id, uint64_t instance_id, WorkerEpoch &epoch) noexcept;
    void                                                  quiesce_worker(size_t worker_id, uint64_t instance_id, WorkerEpoch &epoch) noexcept;

    // Called only by the exact worker thread. The old local owner is released
    // before observed_generation is published.
    [[nodiscard]] bool refresh_worker_snapshot(FilterSnapshot &local_snapshot, uint64_t instance_id, WorkerEpoch &epoch) noexcept;
    [[nodiscard]] bool worker_needs_refresh(uint64_t instance_id, const WorkerEpoch &epoch) const noexcept;

    [[nodiscard]] bool               acquire_retirement_credit(std::stop_token stop_token) noexcept;
    void                             release_uncommitted_credit() noexcept;
    [[nodiscard]] FilterCommitResult commit(FilterSnapshot candidate) noexcept;
    FilterGenerationWaitResult       wait_until_converged(FilterGeneration generation) noexcept;
    FilterGenerationWaitResult       wait_until_reclaimed(FilterGeneration generation) noexcept;

    void               seal_publication() noexcept;
    [[nodiscard]] bool detach_terminal_snapshot() noexcept;

    [[nodiscard]] SnapshotReclaimerResult run_reclaimer(std::stop_token stop_token, SnapshotReclaimerObserver *observer = nullptr) noexcept;
    void                                  request_reclaimer_shutdown() noexcept;
    void                                  inject_reclaimer_failure_for_testing() noexcept;
    void                                  inject_reclaimer_failure_after_next_commit_for_testing() noexcept;

    // The caller must prove that B has been joined and publication has been
    // sealed, so no commit can race this takeover. A may still be alive only
    // as a waiter on the stable committed record. Owners are released solely
    // for records whose exact cohort is already complete.
    [[nodiscard]] bool emergency_reclaim_converged() noexcept;

    [[nodiscard]] FilterVersion         current_version() const noexcept;
    [[nodiscard]] FilterGeneration      current_generation() const noexcept;
    [[nodiscard]] FilterRetirementStats retirement_stats() const noexcept;
    [[nodiscard]] bool                  current_matches(std::string_view domain) const;

private:
    friend struct FilterPublicationTestPeer;

    struct CohortMember final
    {
        size_t       worker_id{0};
        uint64_t     instance_id{0};
        WorkerEpoch *epoch{nullptr};
    };

    struct RetirementRecord final
    {
        explicit RetirementRecord(size_t maximum_workers) { cohort.reserve(maximum_workers); }

        FilterSnapshot                        owner;
        FilterVersion                         version;
        size_t                                published_normalized_rule_bytes{0};
        size_t                                retired_bytes{0};
        std::vector<CohortMember>             cohort;
        std::chrono::steady_clock::time_point committed_at{};
        bool                                  pending{false};
        bool                                  destroying{false};
        bool                                  terminal{false};
    };

    [[nodiscard]] bool                  member_complete(const CohortMember &member, FilterGeneration generation, bool terminal) const noexcept;
    [[nodiscard]] bool                  cohort_complete(const RetirementRecord &record) const noexcept;
    [[nodiscard]] FilterGraceDiagnostic make_diagnostic(const RetirementRecord &record, std::chrono::steady_clock::time_point now) const;
    void                                publish_progress() noexcept;
    void                                reclaim_record(RetirementRecord &record, bool returns_credit) noexcept;
    [[nodiscard]] bool                  reclaim_converged_locked() noexcept;
    [[nodiscard]] RetirementRecord     *next_pending_record_locked() noexcept;

    Config                        config_;
    mutable std::mutex            publication_mutex_;
    FilterSnapshotSlot            active_snapshot_{nullptr};
    std::vector<WorkerEpoch *>    registry_;
    FilterPublicationSink        *publication_sink_{nullptr};
    std::atomic<FilterGeneration> current_generation_{0};
    std::atomic<size_t>           current_rule_count_{0};
    std::atomic<size_t>           current_normalized_rule_bytes_{0};
    std::atomic<bool>             publication_sealed_{false};

    mutable std::mutex          retirement_mutex_;
    std::condition_variable_any retirement_changed_;
    RetirementRecord            retired_;
    RetirementRecord            terminal_;
    bool                        retirement_credit_held_{false};
    size_t                      retired_bytes_{0};
    std::atomic<uint64_t>       progress_sequence_{0};
    FilterGeneration            last_converged_generation_{0};
    FilterGeneration            last_reclaimed_generation_{0};
    bool                        reclaimer_shutdown_requested_{false};
    bool                        reclaimer_failure_requested_{false};
    bool                        reclaimer_failure_after_commit_requested_{false};
    bool                        reclaimer_started_{false};
    bool                        reclaimer_active_{false};
};

} // namespace dns::server
