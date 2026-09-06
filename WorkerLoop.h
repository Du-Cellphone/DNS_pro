#pragma once

#include "DNS_Cache.h"
#include "FilterPublication.h"
#include "common/Expected.h"
#include "protocol/DnsMessage.h"
#include "runtime/Scheduler.h"
#include "runtime/Task.h"
#include "runtime/TimerQueue.h"
#include "runtime/UniqueFd.h"
#include "upstream/UpstreamChannel.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <sys/socket.h>
#include <utility>
#include <vector>

namespace dns::server
{

struct WorkerLoopTestPeer;

struct UpstreamConfig
{
    // MVP accepts an IPv4 literal to avoid resolving the resolver itself.
    std::string                   address{"127.0.0.1"};
    uint16_t                      port{53};
    runtime::TimerQueue::Duration query_timeout{std::chrono::seconds{2}};
    runtime::TimerQueue::Duration id_reuse_guard{std::chrono::seconds{4}};
    size_t                        transaction_id_capacity{65'536};
};

[[nodiscard]] bool is_valid_upstream_config(const UpstreamConfig &config) noexcept;

enum class WorkerInitStep
{
    CreateSocket,
    ConfigureSocket,
    BindSocket,
    ReadBoundAddress,
    CreateEpoll,
    CreateWakeEvent,
    CreateGenerationEvent,
    ValidateUpstream,
    CreateUpstreamSocket,
    ConnectUpstream,
    RegisterListener,
    RegisterWakeEvent,
    RegisterGenerationEvent,
    RegisterUpstream,
};

struct WorkerInitError
{
    WorkerInitStep step;
    int            error_number{0};

    bool operator==(const WorkerInitError &) const = default;
};

enum class WorkerRuntimeStep : uint8_t
{
    StartScheduler,
    StartTimerQueue,
    StartUpstreamChannel,
    AwaitActivation,
    SynchronizeFilter,
    WaitForEvents,
    RuntimeInvariant,
    UnhandledException,
    Shutdown,
    UnexpectedStop,
};

struct WorkerRuntimeError
{
    WorkerRuntimeStep step{WorkerRuntimeStep::UnhandledException};
    int               error_number{0};

    bool operator==(const WorkerRuntimeError &) const = default;
};

enum class WorkerReadyOutcome : uint8_t
{
    Ready,
    InitError,
};

struct WorkerReadyResult
{
    WorkerReadyOutcome                outcome{WorkerReadyOutcome::InitError};
    std::optional<WorkerRuntimeError> error;

    bool operator==(const WorkerReadyResult &) const = default;
};

enum class WorkerRunOutcome : uint8_t
{
    RequestedStop,
    FatalExit,
};

struct WorkerRunResult
{
    WorkerRunOutcome                  outcome{WorkerRunOutcome::FatalExit};
    std::optional<WorkerRuntimeError> error;

    bool operator==(const WorkerRunResult &) const = default;
};

// The observer is owned by the worker's stable control record. Every callback
// is noexcept so the worker can reliably report startup and activation state
// even while unwinding an otherwise-fatal runtime failure.
class WorkerRunObserver
{
public:
    virtual ~WorkerRunObserver() = default;

    enum class GateAction : uint8_t
    {
        Stop,
        RefreshFilter,
        Proceed,
    };

    virtual void                     report_ready(WorkerReadyResult result) noexcept       = 0;
    [[nodiscard]] virtual GateAction await_activation(std::stop_token stop_token) noexcept = 0;
    virtual void                     report_activated() noexcept                           = 0;
    [[nodiscard]] virtual GateAction await_data_plane(std::stop_token stop_token) noexcept = 0;
    virtual void                     report_filter_progress() noexcept                     = 0;
};

struct WorkerStats
{
    uint64_t received_datagrams{0};
    uint64_t truncated_datagrams{0};
    uint64_t parse_errors{0};
    uint64_t unsupported_queries{0};
    uint64_t accepted_queries{0};
    uint64_t blocked_queries{0};
    uint64_t cache_hits{0};
    uint64_t cache_misses{0};
    uint64_t cache_bypasses{0};
    uint64_t cache_inserts{0};
    uint64_t responses_sent{0};
    uint64_t oversized_responses{0};
    uint64_t send_errors{0};
    uint64_t upstream_queries{0};
    uint64_t upstream_responses{0};
    uint64_t upstream_timeouts{0};
    uint64_t upstream_cancellations{0};
    uint64_t upstream_send_errors{0};
    uint64_t upstream_socket_errors{0};
    uint64_t upstream_overloaded{0};
    uint64_t upstream_invalid_responses{0};
    uint64_t upstream_unmatched_responses{0};
    uint64_t internal_errors{0};
};

enum class DatagramOutcome
{
    Dropped,
    Truncated,
    Malformed,
    Unsupported,
    Accepted,
    InternalError,
};

struct DatagramDecision
{
    DatagramOutcome                  outcome{DatagramOutcome::Dropped};
    std::vector<std::byte>           response;
    std::optional<protocol::Message> request;
};

class WorkerLoop final
{
public:
    using CreateResult = std::expected<std::unique_ptr<WorkerLoop>, WorkerInitError>;

    static CreateResult     create(size_t worker_id, uint16_t port, Cache::CacheShard &cache_shard, const UpstreamConfig &upstream_config = {});
    static CreateResult     create(size_t worker_id, uint16_t port, Cache::CacheShard &cache_shard, FilterPublicationState &filter_publication,
                                   FilterSnapshot initial_snapshot, WorkerEpoch &epoch, uint64_t instance_id, const UpstreamConfig &upstream_config = {});
    static DatagramDecision evaluate_datagram(std::span<const std::byte> packet, bool truncated);

    WorkerLoop(const WorkerLoop &)            = delete;
    WorkerLoop &operator=(const WorkerLoop &) = delete;

    // A null observer preserves the standalone/test behavior: after runtime
    // initialization succeeds, the worker is activated immediately.
    [[nodiscard]] WorkerRunResult run(std::stop_token stop_token, WorkerRunObserver *observer = nullptr) noexcept;
    void                          request_stop() const noexcept;
    [[nodiscard]] bool            request_filter_refresh() const noexcept;

    [[nodiscard]] size_t             worker_id() const noexcept { return worker_id_; }
    [[nodiscard]] uint16_t           bound_port() const noexcept { return bound_port_; }
    [[nodiscard]] const WorkerStats &stats() const noexcept { return stats_; }

private:
    friend struct WorkerLoopTestPeer;

    enum class EventKind : uint64_t
    {
        Listener   = 1,
        Wake       = 2,
        Upstream   = 3,
        Generation = 4,
    };

    struct ClientDatagram
    {
        std::vector<std::byte> packet;
        sockaddr_storage       client_address{};
        socklen_t              client_length{0};
        bool                   truncated{false};
    };

    static constexpr size_t kReceiveBudget         = 64;
    static constexpr size_t kUpstreamReceiveBudget = 64;
    static constexpr size_t kTimerBudget           = 64;
    static constexpr size_t kReadyBudget           = 64;
    static constexpr size_t kShutdownResumeBudget  = 4096;

    WorkerLoop(size_t worker_id, Cache::CacheShard &cache_shard, FilterPublicationState *filter_publication = nullptr,
               FilterSnapshot initial_snapshot = {}, WorkerEpoch *epoch = nullptr, uint64_t instance_id = 0)
        : worker_id_(worker_id)
        , cache_shard_(cache_shard)
        , filter_publication_(filter_publication)
        , local_filter_snapshot_(std::move(initial_snapshot))
        , epoch_(epoch)
        , instance_id_(instance_id)
    {
    }

    std::expected<void, WorkerInitError> initialize(uint16_t port, const UpstreamConfig &upstream_config);
    [[nodiscard]] bool                   shutdown_runtime() noexcept;
    void                                 capture_runtime_stats() noexcept;
    [[nodiscard]] bool                   runtime_invariants_hold() const noexcept;
    void                                 drain_wakeup() const noexcept;
    void                                 drain_generation_wakeup() const noexcept;
    [[nodiscard]] bool                   refresh_filter_snapshot() noexcept;
    [[nodiscard]] bool                   matches_filter(const protocol::DomainName &name) const noexcept;
    void                                 drain_listener(std::stop_token stop_token) noexcept;
    runtime::Task<void>                  process_datagram(ClientDatagram datagram);
    void send_response(const std::vector<std::byte> &response, const sockaddr *client_address, socklen_t client_length) noexcept;

    size_t                         worker_id_{0};
    uint16_t                       bound_port_{0};
    Cache::CacheShard             &cache_shard_;
    FilterPublicationState        *filter_publication_{nullptr};
    FilterSnapshot                 local_filter_snapshot_;
    WorkerEpoch                   *epoch_{nullptr};
    uint64_t                       instance_id_{0};
    runtime::UniqueFd              listen_fd_;
    runtime::UniqueFd              epoll_fd_;
    runtime::UniqueFd              wake_fd_;
    runtime::UniqueFd              generation_fd_;
    runtime::UniqueFd              upstream_fd_;
    dns::upstream::UpstreamChannel upstream_channel_;
    // UpstreamChannel and TimerQueue borrow nodes from coroutine frames. Both
    // are declared before Scheduler and therefore destroyed after it.
    runtime::TimerQueue          timer_queue_;
    runtime::Scheduler           scheduler_;
    dns::upstream::ChannelConfig upstream_channel_config_{};
    WorkerStats                  stats_;
    mutable std::stop_source     stop_source_;
    bool                         listener_pending_{false};
    bool                         generation_pending_{false};
    bool                         upstream_pending_{false};
    bool                         upstream_error_pending_{false};
    bool                         upstream_hangup_pending_{false};
    bool                         upstream_usable_{true};
};

} // namespace dns::server
