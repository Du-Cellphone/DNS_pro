#pragma once

#include "DNS_Cache.h"
#include "common/Expected.h"
#include "runtime/Scheduler.h"
#include "runtime/Task.h"
#include "runtime/UniqueFd.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <stop_token>
#include <sys/socket.h>
#include <vector>

namespace dns::server
{

enum class WorkerInitStep
{
    CreateSocket,
    ConfigureSocket,
    BindSocket,
    ReadBoundAddress,
    CreateEpoll,
    CreateWakeEvent,
    RegisterListener,
    RegisterWakeEvent,
};

struct WorkerInitError
{
    WorkerInitStep step;
    int            error_number{0};
};

struct WorkerStats
{
    uint64_t received_datagrams{0};
    uint64_t truncated_datagrams{0};
    uint64_t parse_errors{0};
    uint64_t unsupported_queries{0};
    uint64_t accepted_queries{0};
    uint64_t responses_sent{0};
    uint64_t send_errors{0};
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
    DatagramOutcome        outcome{DatagramOutcome::Dropped};
    std::vector<std::byte> response;
};

class WorkerLoop final
{
public:
    using CreateResult = Expected<std::unique_ptr<WorkerLoop>, WorkerInitError>;

    static CreateResult create(size_t worker_id, uint16_t port, Cache::CacheShard &cache_shard);
    static DatagramDecision evaluate_datagram(std::span<const std::byte> packet, bool truncated);

    WorkerLoop(const WorkerLoop &) = delete;
    WorkerLoop &operator=(const WorkerLoop &) = delete;

    void run(std::stop_token stop_token) noexcept;
    void request_stop() const noexcept;

    [[nodiscard]] size_t             worker_id() const noexcept { return worker_id_; }
    [[nodiscard]] uint16_t           bound_port() const noexcept { return bound_port_; }
    [[nodiscard]] const WorkerStats &stats() const noexcept { return stats_; }

private:
    enum class EventKind : uint64_t
    {
        Listener = 1,
        Wake     = 2,
    };

    struct ClientDatagram
    {
        std::vector<std::byte> packet;
        sockaddr_storage      client_address{};
        socklen_t             client_length{0};
        bool                  truncated{false};
    };

    static constexpr size_t kMaximumDatagramSize = 4096;
    static constexpr size_t kReceiveBudget = 64;
    static constexpr size_t kReadyBudget = 64;
    static constexpr size_t kShutdownResumeBudget = 4096;

    WorkerLoop(size_t worker_id, Cache::CacheShard &cache_shard)
        : worker_id_(worker_id)
        , cache_shard_(cache_shard)
    {
    }

    Expected<void, WorkerInitError> initialize(uint16_t port);
    void drain_wakeup() const noexcept;
    void drain_listener(std::stop_token stop_token) noexcept;
    runtime::Task<void> process_datagram(ClientDatagram datagram);
    void send_response(const std::vector<std::byte> &response, const sockaddr *client_address, socklen_t client_length) noexcept;

    size_t                 worker_id_{0};
    uint16_t               bound_port_{0};
    Cache::CacheShard     &cache_shard_;
    runtime::UniqueFd      listen_fd_;
    runtime::UniqueFd      epoll_fd_;
    runtime::UniqueFd      wake_fd_;
    runtime::Scheduler     scheduler_;
    WorkerStats            stats_;
    mutable std::stop_source stop_source_;
    bool                   listener_pending_{false};
};

} // namespace dns::server
