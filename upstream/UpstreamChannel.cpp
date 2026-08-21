#include "upstream/UpstreamChannel.h"

#include "protocol/DnsParser.h"
#include "protocol/DnsResponse.h"
#include "protocol/DnsWriter.h"

#include <algorithm>
#include <array>
#include <bitset>
#include <cerrno>
#include <cstring>
#include <exception>
#include <limits>
#include <random>
#include <span>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/uio.h>
#include <utility>

namespace dns::upstream
{

QueryAwaiter::QueryAwaiter(UpstreamChannel &channel, protocol::Header header, protocol::Question question,
                           runtime::TimerQueue::TimePoint deadline) noexcept
    : owner_(&channel)
    , header_(std::move(header))
    , question_(std::move(question))
    , deadline_(deadline)
{
}

QueryAwaiter::~QueryAwaiter()
{
    if (owner_ != nullptr)
        owner_->abandon(*this);
}

bool QueryAwaiter::begin(runtime::detail::TaskPromiseBase &task)
{
    if (owner_ == nullptr || state_ != State::Idle)
    {
        state_ = State::Failed;
        error_ = "upstream query awaiter cannot be reused";
        return false;
    }

    switch (owner_->begin(*this, task))
    {
        case UpstreamChannel::BeginResult::Suspended:
            return true;
        case UpstreamChannel::BeginResult::Closed:
            owner_          = nullptr;
            state_          = State::Completed;
            result_.outcome = QueryOutcome::Cancelled;
            return false;
        case UpstreamChannel::BeginResult::Overloaded:
            owner_          = nullptr;
            state_          = State::Completed;
            result_.outcome = QueryOutcome::Overloaded;
            return false;
        case UpstreamChannel::BeginResult::InvalidQuery:
            owner_          = nullptr;
            state_          = State::Completed;
            result_.outcome = QueryOutcome::InvalidQuery;
            return false;
        case UpstreamChannel::BeginResult::SendError:
            owner_          = nullptr;
            state_          = State::Completed;
            result_.outcome = QueryOutcome::SendError;
            return false;
        case UpstreamChannel::BeginResult::WrongThread:
            error_ = "upstream channel used from a non-owner thread";
            break;
        case UpstreamChannel::BeginResult::WrongScheduler:
            error_ = "upstream channel belongs to another scheduler";
            break;
        case UpstreamChannel::BeginResult::TimerFailure:
            error_ = "upstream deadline could not be armed";
            break;
    }

    owner_ = nullptr;
    state_ = State::Failed;
    return false;
}

bool QueryAwaiter::deadline_complete(void *context, runtime::TimerCompletion completion) noexcept
{
    auto &query = *static_cast<QueryAwaiter *>(context);
    return query.owner_ != nullptr && query.owner_->finish_deadline(query, completion);
}

QueryResult QueryAwaiter::await_resume()
{
    if (state_ == State::Failed)
        throw std::logic_error{error_ != nullptr ? error_ : "upstream query failed"};
    if (state_ != State::Completed)
        throw std::logic_error{"upstream query resumed before completion"};
    if (result_.outcome == QueryOutcome::Cancelled)
        throw runtime::OperationCancelled{};
    return std::move(result_);
}

UpstreamChannel::~UpstreamChannel()
{
    if (pending_count_ == 0)
        return;

    // A pending awaiter borrows this channel and its TimerQueue. Destruction
    // must therefore happen on the owner thread, where cancellation can first
    // detach both borrowed registrations and enqueue their coroutine frames.
    if (!on_owner_thread())
        std::terminate();
    accepting_ = false;
    static_cast<void>(cancel_all());
    if (pending_count_ != 0)
        std::terminate();
}

bool UpstreamChannel::start(int socket_fd, runtime::Scheduler &scheduler, runtime::TimerQueue &timers, const ChannelConfig &config)
{
    if (running_ || pending_count_ != 0 || socket_fd < 0 || !scheduler.owns_current_thread() || !timers.is_bound_to(scheduler) ||
        config.query_timeout <= Duration::zero() || config.id_reuse_guard < config.query_timeout || config.transaction_id_capacity == 0 ||
        config.transaction_id_capacity > kTransactionIdSpace || (has_started_ && config != config_) || !discard_socket_input(socket_fd))
        return false;

    std::fill(slots_.begin(), slots_.end(), nullptr);
    stats_ = {};
    if (!has_started_)
        initialize_id_pool(config);
    else
        reclaim_ids(Clock::now());
    if (!validate_id_pool(config.transaction_id_capacity))
    {
        ++stats_.invariant_failures;
        return false;
    }
    scheduler_     = &scheduler;
    timers_        = &timers;
    owner_thread_  = std::this_thread::get_id();
    config_        = config;
    socket_fd_     = socket_fd;
    pending_count_ = 0;
    running_       = true;
    accepting_     = true;
    has_started_   = true;
    return true;
}

bool UpstreamChannel::close() noexcept
{
    if (running_ && !on_owner_thread())
        return false;
    accepting_ = false;
    return true;
}

size_t UpstreamChannel::cancel_all() noexcept
{
    return fail_all(QueryOutcome::Cancelled);
}

bool UpstreamChannel::stop() noexcept
{
    if (running_ && !on_owner_thread())
        return false;
    if (pending_count_ != 0)
        return false;
    if (has_started_ && !validate_id_pool(config_.transaction_id_capacity))
    {
        ++stats_.invariant_failures;
        return false;
    }

    scheduler_    = nullptr;
    timers_       = nullptr;
    owner_thread_ = {};
    socket_fd_    = -1;
    running_      = false;
    accepting_    = false;
    return true;
}

QueryAwaiter UpstreamChannel::query(protocol::Header header, protocol::Question question) noexcept
{
    const TimePoint now         = Clock::now();
    const Duration  timeout     = config_.query_timeout;
    TimePoint       deadline    = TimePoint::max();
    const Duration  since_epoch = now.time_since_epoch();
    if (since_epoch <= Duration::zero() || timeout <= Duration::max() - since_epoch)
        deadline = TimePoint{since_epoch + timeout};
    return QueryAwaiter{*this, std::move(header), std::move(question), deadline};
}

QueryAwaiter UpstreamChannel::query_until(protocol::Header header, protocol::Question question, TimePoint deadline) noexcept
{
    return QueryAwaiter{*this, std::move(header), std::move(question), deadline};
}

UpstreamChannel::BeginResult UpstreamChannel::begin(QueryAwaiter &query, runtime::detail::TaskPromiseBase &task)
{
    if (!running_ || !accepting_)
        return BeginResult::Closed;
    if (!on_owner_thread())
        return BeginResult::WrongThread;
    if (task.scheduler() != scheduler_ || timers_ == nullptr || !timers_->is_bound_to(*scheduler_))
        return BeginResult::WrongScheduler;

    const TimePoint now = Clock::now();
    auto            id  = allocate_id(now);
    if (!id)
    {
        ++stats_.overloaded;
        return BeginResult::Overloaded;
    }

    protocol::Header upstream_header = query.header_;
    upstream_header.id               = *id;
    const std::span<const protocol::Question> questions{&query.question_, 1};
    auto                                      wire = [&]() -> protocol::WriteResult
    {
        try
        {
            return protocol::serialize_query(upstream_header, questions, protocol::kUpstreamQueryBudget);
        }
        catch (...)
        {
            release_id(*id, now, false);
            throw;
        }
    }();
    if (!wire)
    {
        release_id(*id, now, false);
        return BeginResult::InvalidQuery;
    }

    query.owner_          = this;
    query.task_           = &task;
    query.transaction_id_ = *id;
    query.state_          = QueryAwaiter::State::Pending;
    slots_[*id]           = &query;
    ++pending_count_;

    runtime::TimerQueue::ArmResult armed;
    try
    {
        armed = timers_->arm(query.timer_, query.deadline_, &QueryAwaiter::deadline_complete, &query);
    }
    catch (...)
    {
        rollback_begin(query);
        throw;
    }
    if (armed != runtime::TimerQueue::ArmResult::Armed)
    {
        rollback_begin(query);
        return armed == runtime::TimerQueue::ArmResult::Closed ? BeginResult::Closed : BeginResult::TimerFailure;
    }

    ssize_t sent;
    do
    {
        sent = ::send(socket_fd_, wire->data(), wire->size(), 0);
    } while (sent < 0 && errno == EINTR);

    if (sent != static_cast<ssize_t>(wire->size()))
    {
        const int error_number = sent < 0 ? errno : EIO;
        rollback_begin(query);
        query.result_.error_number = error_number;
        ++stats_.send_errors;
        return BeginResult::SendError;
    }

    ++stats_.queries_sent;
    return BeginResult::Suspended;
}

void UpstreamChannel::rollback_begin(QueryAwaiter &query) noexcept
{
    if (query.timer_.armed() && timers_ != nullptr)
        static_cast<void>(timers_->disarm(query.timer_));
    if (query.transaction_id_ < config_.transaction_id_capacity && slots_[query.transaction_id_] == &query)
    {
        slots_[query.transaction_id_] = nullptr;
        --pending_count_;
        release_id(query.transaction_id_, Clock::now(), false);
    }
    query.owner_ = nullptr;
    query.task_  = nullptr;
    query.state_ = QueryAwaiter::State::Idle;
}

void UpstreamChannel::abandon(QueryAwaiter &query) noexcept
{
    if (query.owner_ != this || query.state_ != QueryAwaiter::State::Pending)
        return;

    if (query.transaction_id_ >= config_.transaction_id_capacity || slots_[query.transaction_id_] != &query)
    {
        ++stats_.invariant_failures;
        query.owner_ = nullptr;
        query.task_  = nullptr;
        return;
    }

    slots_[query.transaction_id_] = nullptr;
    --pending_count_;
    if (query.timer_.armed() && timers_ != nullptr && !timers_->disarm(query.timer_))
        ++stats_.invariant_failures;
    release_id(query.transaction_id_, Clock::now(), true);
    query.owner_          = nullptr;
    query.task_           = nullptr;
    query.state_          = QueryAwaiter::State::Completed;
    query.result_.outcome = QueryOutcome::Cancelled;
    ++stats_.cancellations;
}

bool UpstreamChannel::finish(QueryAwaiter &query, QueryOutcome outcome, std::vector<std::byte> response, int error_number) noexcept
{
    if (query.owner_ != this || query.state_ != QueryAwaiter::State::Pending || query.transaction_id_ >= config_.transaction_id_capacity ||
        slots_[query.transaction_id_] != &query)
        return false;

    slots_[query.transaction_id_] = nullptr;
    --pending_count_;
    if (query.timer_.armed() && timers_ != nullptr && !timers_->disarm(query.timer_))
        ++stats_.invariant_failures;
    release_id(query.transaction_id_, Clock::now(), true);

    runtime::detail::TaskPromiseBase *task = std::exchange(query.task_, nullptr);
    query.result_.outcome                  = outcome;
    query.result_.response                 = std::move(response);
    query.result_.error_number             = error_number;
    query.state_                           = QueryAwaiter::State::Completed;
    query.owner_                           = nullptr;

    switch (outcome)
    {
        case QueryOutcome::Response:
            ++stats_.responses_completed;
            break;
        case QueryOutcome::Timeout:
            ++stats_.timeouts;
            break;
        case QueryOutcome::Cancelled:
            ++stats_.cancellations;
            break;
        case QueryOutcome::SocketError:
            ++stats_.socket_errors;
            break;
        case QueryOutcome::SendError:
            ++stats_.send_errors;
            break;
        case QueryOutcome::Overloaded:
            ++stats_.overloaded;
            break;
        case QueryOutcome::InvalidQuery:
            break;
    }

    if (task == nullptr || scheduler_ == nullptr || scheduler_->schedule(*task) != runtime::Scheduler::ScheduleResult::Scheduled)
    {
        ++stats_.invariant_failures;
        return false;
    }
    return true;
}

bool UpstreamChannel::finish_deadline(QueryAwaiter &query, runtime::TimerCompletion completion) noexcept
{
    return finish(query, completion == runtime::TimerCompletion::Expired ? QueryOutcome::Timeout : QueryOutcome::Cancelled);
}

PacketResult UpstreamChannel::handle_datagram(std::span<const std::byte> packet, bool truncated) noexcept
{
    if (!running_ || !on_owner_thread())
        return PacketResult::InvariantFailure;
    if (truncated || packet.size() > protocol::kUpstreamReceiveBufferSize)
    {
        ++stats_.invalid_responses;
        return PacketResult::Invalid;
    }

    const auto id = protocol::transaction_id(packet);
    if (!id || *id >= config_.transaction_id_capacity || slots_[*id] == nullptr)
    {
        ++stats_.unmatched_responses;
        return PacketResult::Unmatched;
    }

    QueryAwaiter *query = slots_[*id];
    try
    {
        protocol::ParseLimits limits;
        limits.maximum_packet_size = protocol::kUpstreamReceiveBufferSize;
        auto parsed                = protocol::parse_message(packet, limits);
        if (!parsed || !protocol::validate_upstream_response(*parsed, *id, query->header_.opcode, query->question_))
        {
            ++stats_.invalid_responses;
            return PacketResult::Invalid;
        }

        std::vector<std::byte> response = std::move(parsed->wire_image);
        if (!protocol::rewrite_transaction_id(response, query->header_.id))
        {
            ++stats_.invariant_failures;
            return PacketResult::InvariantFailure;
        }
        return finish(*query, QueryOutcome::Response, std::move(response)) ? PacketResult::Completed : PacketResult::InvariantFailure;
    }
    catch (...)
    {
        ++stats_.invariant_failures;
        static_cast<void>(finish(*query, QueryOutcome::SocketError, {}, ENOMEM));
        return PacketResult::InvariantFailure;
    }
}

DrainResult UpstreamChannel::drain(size_t budget) noexcept
{
    DrainResult result;
    if (!running_ || !on_owner_thread())
        return result;

    std::array<std::byte, protocol::kUpstreamReceiveBufferSize> buffer{};
    while (result.datagrams < budget)
    {
        iovec  io_vector{buffer.data(), buffer.size()};
        msghdr message{};
        message.msg_iov    = &io_vector;
        message.msg_iovlen = 1;

        const ssize_t received = ::recvmsg(socket_fd_, &message, MSG_TRUNC);
        if (received < 0)
        {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return result;

            const int error_number = errno;
            result.socket_error    = true;
            static_cast<void>(fail_all(QueryOutcome::SocketError, error_number));
            return result;
        }

        ++result.datagrams;
        const bool   truncated = (message.msg_flags & MSG_TRUNC) != 0 || static_cast<size_t>(received) > buffer.size();
        const size_t available = std::min(static_cast<size_t>(received), buffer.size());
        static_cast<void>(handle_datagram(std::span<const std::byte>{buffer}.first(available), truncated));
    }

    result.has_more = true;
    return result;
}

size_t UpstreamChannel::fail_all(QueryOutcome outcome, int error_number) noexcept
{
    if (!running_ || !on_owner_thread() || (outcome != QueryOutcome::Cancelled && outcome != QueryOutcome::SocketError))
        return 0;

    size_t completed = 0;
    for (size_t index = 0; index < config_.transaction_id_capacity; ++index)
    {
        QueryAwaiter *query = slots_[index];
        if (query != nullptr && finish(*query, outcome, {}, error_number))
            ++completed;
    }
    return completed;
}

bool UpstreamChannel::on_owner_thread() const noexcept
{
    return running_ && owner_thread_ == std::this_thread::get_id();
}

std::optional<uint16_t> UpstreamChannel::allocate_id(TimePoint now) noexcept
{
    reclaim_ids(now);
    while (!free_ids_.empty())
    {
        const uint16_t id = free_ids_.back();
        free_ids_.pop_back();
        if (id >= config_.transaction_id_capacity || id_states_[id] != IdState::Free || slots_[id] != nullptr)
        {
            ++stats_.invariant_failures;
            continue;
        }
        id_states_[id] = IdState::Pending;
        return id;
    }
    return std::nullopt;
}

void UpstreamChannel::release_id(uint16_t id, TimePoint now, bool quarantine) noexcept
{
    if (id >= config_.transaction_id_capacity || id_states_[id] != IdState::Pending)
    {
        ++stats_.invariant_failures;
        return;
    }

    if (!quarantine || config_.id_reuse_guard <= Duration::zero())
    {
        id_states_[id] = IdState::Free;
        insert_free_id(id);
        return;
    }

    id_states_[id] = IdState::Retired;
    retired_ids_.push_back(RetiredId{guarded_reuse_time(now), id});
    std::push_heap(retired_ids_.begin(), retired_ids_.end(), RetiredLater{});
}

void UpstreamChannel::initialize_id_pool(const ChannelConfig &config)
{
    std::fill(id_states_.begin(), id_states_.end(), IdState::Unavailable);
    free_ids_.clear();
    retired_ids_.clear();
    free_ids_.reserve(config.transaction_id_capacity);
    retired_ids_.reserve(config.transaction_id_capacity);

    if (config.randomize_transaction_ids)
    {
        std::random_device                             source;
        std::array<std::random_device::result_type, 8> entropy{};
        for (auto &value : entropy)
            value = source();
        entropy.front() ^= config.initial_transaction_id;
        std::seed_seq seed{entropy.begin(), entropy.end()};
        random_engine_.seed(seed);

        for (size_t id = 0; id < config.transaction_id_capacity; ++id)
            free_ids_.push_back(static_cast<uint16_t>(id));
        std::shuffle(free_ids_.begin(), free_ids_.end(), random_engine_);
    }
    else
    {
        const size_t first = static_cast<size_t>(config.initial_transaction_id) % config.transaction_id_capacity;
        for (size_t remaining = config.transaction_id_capacity; remaining != 0; --remaining)
            free_ids_.push_back(static_cast<uint16_t>((first + remaining - 1) % config.transaction_id_capacity));
    }

    for (uint16_t id : free_ids_)
        id_states_[id] = IdState::Free;
}

void UpstreamChannel::reclaim_ids(TimePoint now) noexcept
{
    while (!retired_ids_.empty() && retired_ids_.front().reusable_at <= now)
    {
        std::pop_heap(retired_ids_.begin(), retired_ids_.end(), RetiredLater{});
        const RetiredId retired = retired_ids_.back();
        retired_ids_.pop_back();
        if (retired.id >= config_.transaction_id_capacity || id_states_[retired.id] != IdState::Retired || slots_[retired.id] != nullptr)
        {
            ++stats_.invariant_failures;
            continue;
        }
        id_states_[retired.id] = IdState::Free;
        insert_free_id(retired.id);
    }
}

void UpstreamChannel::insert_free_id(uint16_t id) noexcept
{
    free_ids_.push_back(id);
    if (!config_.randomize_transaction_ids || free_ids_.size() < 2)
        return;

    std::uniform_int_distribution<size_t> distribution{0, free_ids_.size() - 1};
    std::swap(free_ids_.back(), free_ids_[distribution(random_engine_)]);
}

bool UpstreamChannel::validate_id_pool(size_t capacity) const noexcept
{
    // This audit runs only at start/stop boundaries, where no coroutine may
    // still borrow a slot. Avoid dereferencing a suspicious slot pointer while
    // diagnosing a corrupted idle pool.
    if (capacity == 0 || capacity > kTransactionIdSpace || pending_count_ != 0 || free_ids_.size() + retired_ids_.size() != capacity ||
        !std::is_heap(retired_ids_.begin(), retired_ids_.end(), RetiredLater{}))
        return false;

    std::bitset<kTransactionIdSpace> seen;
    for (uint16_t id : free_ids_)
    {
        if (id >= capacity || seen.test(id) || id_states_[id] != IdState::Free || slots_[id] != nullptr)
            return false;
        seen.set(id);
    }
    for (const RetiredId &retired : retired_ids_)
    {
        const uint16_t id = retired.id;
        if (id >= capacity || seen.test(id) || id_states_[id] != IdState::Retired || slots_[id] != nullptr)
            return false;
        seen.set(id);
    }

    for (size_t id = 0; id < kTransactionIdSpace; ++id)
    {
        if (id >= capacity)
        {
            if (id_states_[id] != IdState::Unavailable || slots_[id] != nullptr)
                return false;
            continue;
        }
        if (!seen.test(id) || id_states_[id] == IdState::Pending || slots_[id] != nullptr)
            return false;
    }
    return seen.count() == capacity;
}

UpstreamChannel::TimePoint UpstreamChannel::guarded_reuse_time(TimePoint now) const noexcept
{
    const Duration guard = config_.id_reuse_guard;
    if (guard <= Duration::zero())
        return now;
    const Duration since_epoch = now.time_since_epoch();
    if (since_epoch > Duration::zero() && guard > Duration::max() - since_epoch)
        return TimePoint::max();
    return TimePoint{since_epoch + guard};
}

bool UpstreamChannel::discard_socket_input(int socket_fd) noexcept
{
    std::array<std::byte, protocol::kUpstreamReceiveBufferSize> buffer{};
    constexpr size_t                          maximum_discarded_datagrams = kTransactionIdSpace;
    size_t                                    discarded                   = 0;

    while (discarded < maximum_discarded_datagrams)
    {
        const ssize_t received = ::recv(socket_fd, buffer.data(), buffer.size(), MSG_DONTWAIT | MSG_TRUNC);
        if (received >= 0)
        {
            ++discarded;
            continue;
        }
        if (errno == EINTR)
            continue;
        return errno == EAGAIN || errno == EWOULDBLOCK;
    }
    return false;
}

} // namespace dns::upstream
