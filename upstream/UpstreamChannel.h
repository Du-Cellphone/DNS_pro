#pragma once

#include "protocol/DnsLimits.h"
#include "protocol/DnsMessage.h"
#include "runtime/Scheduler.h"
#include "runtime/TimerQueue.h"

#include <array>
#include <chrono>
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <random>
#include <span>
#include <thread>
#include <vector>

namespace dns::upstream
{

class UpstreamChannel;

enum class QueryOutcome : uint8_t
{
    Response,
    Timeout,
    SendError,
    SocketError,
    Overloaded,
    InvalidQuery,
    Cancelled,
};

struct QueryResult
{
    QueryOutcome           outcome{QueryOutcome::InvalidQuery};
    std::vector<std::byte> response;
    int                    error_number{0};
};

struct ChannelConfig
{
    runtime::TimerQueue::Duration query_timeout{std::chrono::seconds{2}};
    runtime::TimerQueue::Duration id_reuse_guard{std::chrono::seconds{4}};
    size_t                        transaction_id_capacity{65'536};
    uint16_t                      initial_transaction_id{0};
    bool                          randomize_transaction_ids{true};

    bool operator==(const ChannelConfig &) const = default;
};

struct ChannelStats
{
    uint64_t queries_sent{0};
    uint64_t responses_completed{0};
    uint64_t timeouts{0};
    uint64_t cancellations{0};
    uint64_t send_errors{0};
    uint64_t socket_errors{0};
    uint64_t overloaded{0};
    uint64_t invalid_responses{0};
    uint64_t unmatched_responses{0};
    uint64_t invariant_failures{0};
};

enum class PacketResult : uint8_t
{
    Completed,
    Invalid,
    Unmatched,
    InvariantFailure,
};

struct DrainResult
{
    size_t datagrams{0};
    bool   has_more{false};
    bool   socket_error{false};
};

class QueryAwaiter final
{
public:
    QueryAwaiter(UpstreamChannel &channel, protocol::Header header, protocol::Question question, runtime::TimerQueue::TimePoint deadline) noexcept;
    ~QueryAwaiter();

    QueryAwaiter(const QueryAwaiter &)            = delete;
    QueryAwaiter &operator=(const QueryAwaiter &) = delete;
    QueryAwaiter(QueryAwaiter &&)                 = delete;
    QueryAwaiter &operator=(QueryAwaiter &&)      = delete;

    [[nodiscard]] bool await_ready() const noexcept { return false; }

    template <runtime::detail::TaskPromise Promise>
    bool await_suspend(std::coroutine_handle<Promise> handle)
    {
        auto &task = static_cast<runtime::detail::TaskPromiseBase &>(handle.promise());
        if (task.scheduler() == nullptr)
        {
            owner_ = nullptr;
            state_ = State::Failed;
            error_ = "upstream query is not bound to a scheduler";
            return false;
        }
        if (task.stop_token().stop_requested())
        {
            owner_          = nullptr;
            state_          = State::Completed;
            result_.outcome = QueryOutcome::Cancelled;
            return false;
        }

        return begin(task);
    }

    QueryResult await_resume();

private:
    friend class UpstreamChannel;

    enum class State : uint8_t
    {
        Idle,
        Pending,
        Completed,
        Failed,
    };

    [[nodiscard]] bool        begin(runtime::detail::TaskPromiseBase &task);
    [[nodiscard]] static bool deadline_complete(void *context, runtime::TimerCompletion completion) noexcept;

    UpstreamChannel                  *owner_{nullptr};
    runtime::detail::TaskPromiseBase *task_{nullptr};
    protocol::Header                  header_;
    protocol::Question                question_;
    runtime::TimerQueue::TimePoint    deadline_{};
    runtime::TimerRegistration        timer_{};
    QueryResult                       result_{};
    const char                       *error_{nullptr};
    uint16_t                          transaction_id_{0};
    State                             state_{State::Idle};
};

// One UpstreamChannel belongs to one worker thread and one connected UDP
// socket. Its fixed ID table only borrows QueryAwaiter objects in coroutine
// frames; Scheduler remains the sole owner of those frames.
class UpstreamChannel final
{
public:
    using Clock     = runtime::TimerQueue::Clock;
    using TimePoint = runtime::TimerQueue::TimePoint;
    using Duration  = runtime::TimerQueue::Duration;

    // Retained as a source-compatible alias for tests and callers that use a
    // receive buffer sized to the channel's classic UDP service boundary.
    static constexpr size_t kMaximumPacketSize  = protocol::kUpstreamReceiveBufferSize;
    static constexpr size_t kTransactionIdSpace = 65'536;

    UpstreamChannel() = default;
    ~UpstreamChannel();

    UpstreamChannel(const UpstreamChannel &)            = delete;
    UpstreamChannel &operator=(const UpstreamChannel &) = delete;
    UpstreamChannel(UpstreamChannel &&)                 = delete;
    UpstreamChannel &operator=(UpstreamChannel &&)      = delete;

    [[nodiscard]] bool   start(int socket_fd, runtime::Scheduler &scheduler, runtime::TimerQueue &timers, const ChannelConfig &config);
    [[nodiscard]] bool   close() noexcept;
    [[nodiscard]] size_t cancel_all() noexcept;
    [[nodiscard]] bool   stop() noexcept;

    [[nodiscard]] QueryAwaiter query(protocol::Header header, protocol::Question question) noexcept;
    [[nodiscard]] QueryAwaiter query_until(protocol::Header header, protocol::Question question, TimePoint deadline) noexcept;

    [[nodiscard]] PacketResult handle_datagram(std::span<const std::byte> packet, bool truncated = false) noexcept;
    [[nodiscard]] DrainResult  drain(size_t budget) noexcept;
    [[nodiscard]] size_t       fail_all(QueryOutcome outcome, int error_number = 0) noexcept;

    [[nodiscard]] int                 fd() const noexcept { return socket_fd_; }
    [[nodiscard]] size_t              pending_count() const noexcept { return pending_count_; }
    [[nodiscard]] bool                accepting() const noexcept { return accepting_; }
    [[nodiscard]] const ChannelStats &stats() const noexcept { return stats_; }
    [[nodiscard]] Duration            query_timeout() const noexcept { return config_.query_timeout; }

private:
    friend class QueryAwaiter;

    enum class IdState : uint8_t
    {
        Unavailable,
        Free,
        Pending,
        Retired,
    };

    struct RetiredId
    {
        TimePoint reusable_at{};
        uint16_t  id{0};
    };

    struct RetiredLater
    {
        [[nodiscard]] bool operator()(const RetiredId &left, const RetiredId &right) const noexcept
        {
            if (left.reusable_at != right.reusable_at)
                return left.reusable_at > right.reusable_at;
            return left.id > right.id;
        }
    };

    enum class BeginResult : uint8_t
    {
        Suspended,
        Closed,
        WrongThread,
        WrongScheduler,
        Overloaded,
        InvalidQuery,
        TimerFailure,
        SendError,
    };

    [[nodiscard]] BeginResult begin(QueryAwaiter &query, runtime::detail::TaskPromiseBase &task);
    void                      abandon(QueryAwaiter &query) noexcept;
    [[nodiscard]] bool        finish(QueryAwaiter &query, QueryOutcome outcome, std::vector<std::byte> response = {}, int error_number = 0) noexcept;
    [[nodiscard]] bool        finish_deadline(QueryAwaiter &query, runtime::TimerCompletion completion) noexcept;

    [[nodiscard]] bool                    on_owner_thread() const noexcept;
    [[nodiscard]] std::optional<uint16_t> allocate_id(TimePoint now) noexcept;
    void                                  release_id(uint16_t id, TimePoint now, bool quarantine) noexcept;
    void                                  initialize_id_pool(const ChannelConfig &config);
    void                                  reclaim_ids(TimePoint now) noexcept;
    void                                  insert_free_id(uint16_t id) noexcept;
    [[nodiscard]] bool                    validate_id_pool(size_t capacity) const noexcept;
    void                                  rollback_begin(QueryAwaiter &query) noexcept;
    [[nodiscard]] TimePoint               guarded_reuse_time(TimePoint now) const noexcept;
    [[nodiscard]] static bool             discard_socket_input(int socket_fd) noexcept;

    std::array<QueryAwaiter *, kTransactionIdSpace> slots_{};
    std::array<IdState, kTransactionIdSpace>        id_states_{};
    std::vector<uint16_t>                           free_ids_;
    std::vector<RetiredId>                          retired_ids_;
    std::mt19937_64                                 random_engine_{};
    runtime::Scheduler                             *scheduler_{nullptr};
    runtime::TimerQueue                            *timers_{nullptr};
    std::thread::id                                 owner_thread_{};
    ChannelConfig                                   config_{};
    ChannelStats                                    stats_{};
    int                                             socket_fd_{-1};
    size_t                                          pending_count_{0};
    bool                                            running_{false};
    bool                                            accepting_{false};
    bool                                            has_started_{false};
};

} // namespace dns::upstream
