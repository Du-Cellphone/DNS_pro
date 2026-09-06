#include "WorkerLoop.h"

#include "CachePolicy.h"
#include "protocol/DnsLimits.h"
#include "protocol/DnsParser.h"
#include "protocol/DnsQuery.h"
#include "protocol/DnsWriter.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <span>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <utility>
#include <vector>

namespace dns::server
{
namespace
{

std::unexpected<WorkerInitError> init_failure(WorkerInitStep step) noexcept
{
    return std::unexpected(WorkerInitError{step, errno});
}

protocol::WriteResult make_cache_hit_response(const protocol::Message &request, const Cache::CacheHit &hit, size_t maximum_size)
{
    if (request.questions.size() != 1)
        return std::unexpected(protocol::WriteError{protocol::WriteErrorCode::WrongQuestionCount});

    const uint16_t                           type = request.questions.front().type;
    std::vector<protocol::AddressAnswerView> answers;
    answers.reserve(hit.addresses.size());
    for (const Cache::IPAddress &address : hit.addresses)
    {
        const auto bytes = std::as_bytes(std::span{address.bytes});
        if (type == static_cast<uint16_t>(protocol::RecordType::A) && address.is_v4())
            answers.push_back(protocol::AddressAnswerView{bytes.first(4)});
        else if (type == static_cast<uint16_t>(protocol::RecordType::AAAA) && address.is_v6())
            answers.push_back(protocol::AddressAnswerView{bytes});
        else
            return std::unexpected(protocol::WriteError{protocol::WriteErrorCode::InvalidAddressLength});
    }
    return protocol::make_address_response(request, answers, hit.remaining_ttl, true, maximum_size);
}

} // namespace

bool is_valid_upstream_config(const UpstreamConfig &config) noexcept
{
    if (config.address.empty() || config.port == 0 || config.query_timeout <= runtime::TimerQueue::Duration::zero() ||
        config.id_reuse_guard < config.query_timeout || config.transaction_id_capacity == 0 ||
        config.transaction_id_capacity > dns::upstream::UpstreamChannel::kTransactionIdSpace)
        return false;

    in_addr address{};
    return ::inet_pton(AF_INET, config.address.c_str(), &address) == 1;
}

DatagramDecision WorkerLoop::evaluate_datagram(std::span<const std::byte> packet, bool truncated)
{
    if (truncated || packet.size() > protocol::kDownstreamReceiveBufferSize)
    {
        // MSG_TRUNC gives us the original datagram length while the span only
        // exposes the safely received prefix. Do not parse that partial DNS
        // message. A response prefix must be dropped to avoid response loops;
        // a query prefix with a usable ID/QR bit gets a header-only FORMERR.
        if (packet.size() < 3 || (std::to_integer<uint8_t>(packet[2]) & 0x80U) != 0)
            return DatagramDecision{DatagramOutcome::Dropped, {}, std::nullopt};

        auto format_error =
            protocol::make_header_only_error_response(packet, protocol::ResponseCode::FormErr, true, protocol::kDownstreamResponseBudget);
        return DatagramDecision{DatagramOutcome::Truncated, format_error ? std::move(*format_error) : std::vector<std::byte>{}, std::nullopt};
    }

    auto parsed = protocol::parse_message(packet);
    if (!parsed)
    {
        auto format_error = protocol::make_format_error_response(packet, true, protocol::kDownstreamResponseBudget);
        return DatagramDecision{DatagramOutcome::Malformed, format_error ? std::move(*format_error) : std::vector<std::byte>{}, std::nullopt};
    }

    auto query = protocol::validate_mvp_query(*parsed);
    if (!query)
    {
        if (query.error().code == protocol::QueryErrorCode::NotAQuery)
            return DatagramDecision{DatagramOutcome::Dropped, {}, std::nullopt};

        auto response =
            protocol::make_error_response(*parsed, protocol::response_code_for(query.error().code), true, protocol::kDownstreamResponseBudget);
        if (!response)
            return DatagramDecision{DatagramOutcome::InternalError, {}, std::nullopt};
        return DatagramDecision{DatagramOutcome::Unsupported, std::move(*response), std::nullopt};
    }

    return DatagramDecision{DatagramOutcome::Accepted, {}, std::move(*parsed)};
}

WorkerLoop::CreateResult WorkerLoop::create(size_t worker_id, uint16_t port, Cache::CacheShard &cache_shard, const UpstreamConfig &upstream_config)
{
    auto worker      = std::unique_ptr<WorkerLoop>{new WorkerLoop{worker_id, cache_shard}};
    auto initialized = worker->initialize(port, upstream_config);
    if (!initialized)
        return std::unexpected(initialized.error());
    return worker;
}

WorkerLoop::CreateResult WorkerLoop::create(size_t worker_id, uint16_t port, Cache::CacheShard &cache_shard,
                                            FilterPublicationState &filter_publication, FilterSnapshot initial_snapshot, WorkerEpoch &epoch,
                                            uint64_t instance_id, const UpstreamConfig &upstream_config)
{
    auto worker =
        std::unique_ptr<WorkerLoop>{new WorkerLoop{worker_id, cache_shard, &filter_publication, std::move(initial_snapshot), &epoch, instance_id}};
    auto initialized = worker->initialize(port, upstream_config);
    if (!initialized)
        return std::unexpected(initialized.error());
    return worker;
}

std::expected<void, WorkerInitError> WorkerLoop::initialize(uint16_t port, const UpstreamConfig &upstream_config)
{
    runtime::UniqueFd listener{::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)};
    if (!listener)
        return init_failure(WorkerInitStep::CreateSocket);

    int enabled = 1;
    if (::setsockopt(listener.get(), SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) < 0 ||
        ::setsockopt(listener.get(), SOL_SOCKET, SO_REUSEPORT, &enabled, sizeof(enabled)) < 0)
        return init_failure(WorkerInitStep::ConfigureSocket);

    sockaddr_in address{};
    address.sin_family      = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port        = htons(port);
    if (::bind(listener.get(), reinterpret_cast<sockaddr *>(&address), sizeof(address)) < 0)
        return init_failure(WorkerInitStep::BindSocket);

    socklen_t address_length = sizeof(address);
    if (::getsockname(listener.get(), reinterpret_cast<sockaddr *>(&address), &address_length) < 0)
        return init_failure(WorkerInitStep::ReadBoundAddress);

    runtime::UniqueFd epoll{::epoll_create1(EPOLL_CLOEXEC)};
    if (!epoll)
        return init_failure(WorkerInitStep::CreateEpoll);

    runtime::UniqueFd wake{::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC)};
    if (!wake)
        return init_failure(WorkerInitStep::CreateWakeEvent);

    runtime::UniqueFd generation;
    if (filter_publication_ != nullptr)
    {
        generation.reset(::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC));
        if (!generation)
            return init_failure(WorkerInitStep::CreateGenerationEvent);
    }

    if (!is_valid_upstream_config(upstream_config))
    {
        errno = EINVAL;
        return init_failure(WorkerInitStep::ValidateUpstream);
    }

    sockaddr_in upstream_address{};
    upstream_address.sin_family = AF_INET;
    upstream_address.sin_port   = htons(upstream_config.port);
    static_cast<void>(::inet_pton(AF_INET, upstream_config.address.c_str(), &upstream_address.sin_addr));

    runtime::UniqueFd upstream_socket{::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)};
    if (!upstream_socket)
        return init_failure(WorkerInitStep::CreateUpstreamSocket);
    if (::connect(upstream_socket.get(), reinterpret_cast<const sockaddr *>(&upstream_address), sizeof(upstream_address)) < 0)
        return init_failure(WorkerInitStep::ConnectUpstream);

    epoll_event listener_event{};
    listener_event.events   = EPOLLIN | EPOLLET;
    listener_event.data.u64 = static_cast<uint64_t>(EventKind::Listener);
    if (::epoll_ctl(epoll.get(), EPOLL_CTL_ADD, listener.get(), &listener_event) < 0)
        return init_failure(WorkerInitStep::RegisterListener);

    epoll_event wake_event{};
    wake_event.events   = EPOLLIN;
    wake_event.data.u64 = static_cast<uint64_t>(EventKind::Wake);
    if (::epoll_ctl(epoll.get(), EPOLL_CTL_ADD, wake.get(), &wake_event) < 0)
        return init_failure(WorkerInitStep::RegisterWakeEvent);

    if (generation)
    {
        epoll_event generation_event{};
        generation_event.events   = EPOLLIN;
        generation_event.data.u64 = static_cast<uint64_t>(EventKind::Generation);
        if (::epoll_ctl(epoll.get(), EPOLL_CTL_ADD, generation.get(), &generation_event) < 0)
            return init_failure(WorkerInitStep::RegisterGenerationEvent);
    }

    epoll_event upstream_event{};
    upstream_event.events   = EPOLLIN | EPOLLET;
    upstream_event.data.u64 = static_cast<uint64_t>(EventKind::Upstream);
    if (::epoll_ctl(epoll.get(), EPOLL_CTL_ADD, upstream_socket.get(), &upstream_event) < 0)
        return init_failure(WorkerInitStep::RegisterUpstream);

    sockaddr_in upstream_local{};
    socklen_t   upstream_local_length = sizeof(upstream_local);
    uint16_t    upstream_seed         = static_cast<uint16_t>((worker_id_ * 0x9e37U) & 0xffffU);
    if (::getsockname(upstream_socket.get(), reinterpret_cast<sockaddr *>(&upstream_local), &upstream_local_length) == 0)
        upstream_seed ^= ntohs(upstream_local.sin_port);

    bound_port_                                      = ntohs(address.sin_port);
    listen_fd_                                       = std::move(listener);
    epoll_fd_                                        = std::move(epoll);
    wake_fd_                                         = std::move(wake);
    generation_fd_                                   = std::move(generation);
    upstream_fd_                                     = std::move(upstream_socket);
    upstream_channel_config_.query_timeout           = upstream_config.query_timeout;
    upstream_channel_config_.id_reuse_guard          = upstream_config.id_reuse_guard;
    upstream_channel_config_.transaction_id_capacity = upstream_config.transaction_id_capacity;
    upstream_channel_config_.initial_transaction_id  = upstream_seed;
    return {};
}

WorkerRunResult WorkerLoop::run(std::stop_token thread_stop_token, WorkerRunObserver *observer) noexcept
{
    const auto requested_stop = [] { return WorkerRunResult{WorkerRunOutcome::RequestedStop, std::nullopt}; };
    const auto fatal_exit     = [](WorkerRuntimeStep step, int error_number = 0)
    { return WorkerRunResult{WorkerRunOutcome::FatalExit, WorkerRuntimeError{step, error_number}}; };
    const auto init_error = [](WorkerRuntimeStep step, int error_number = 0)
    { return WorkerReadyResult{WorkerReadyOutcome::InitError, WorkerRuntimeError{step, error_number}}; };

    const std::stop_token          stop_token = stop_source_.get_token();
    std::optional<WorkerRunResult> result;
    bool                           ready_reported{false};
    bool                           activated{false};

    try
    {
        std::stop_callback          forward_stop{thread_stop_token, [this] { request_stop(); }};
        std::array<epoll_event, 64> events{};

        if (!scheduler_.start(stop_token))
        {
            result.emplace(fatal_exit(WorkerRuntimeStep::StartScheduler));
            if (observer != nullptr)
            {
                observer->report_ready(init_error(WorkerRuntimeStep::StartScheduler));
                ready_reported = true;
            }
        }
        else if (!timer_queue_.start(scheduler_))
        {
            result.emplace(fatal_exit(WorkerRuntimeStep::StartTimerQueue));
            if (observer != nullptr)
            {
                observer->report_ready(init_error(WorkerRuntimeStep::StartTimerQueue));
                ready_reported = true;
            }
        }
        else if (!upstream_channel_.start(upstream_fd_.get(), scheduler_, timer_queue_, upstream_channel_config_))
        {
            result.emplace(fatal_exit(WorkerRuntimeStep::StartUpstreamChannel));
            if (observer != nullptr)
            {
                observer->report_ready(init_error(WorkerRuntimeStep::StartUpstreamChannel));
                ready_reported = true;
            }
        }
        else
        {
            if (filter_publication_ != nullptr && !refresh_filter_snapshot())
            {
                result.emplace(fatal_exit(WorkerRuntimeStep::SynchronizeFilter));
                if (observer != nullptr)
                {
                    observer->report_ready(init_error(WorkerRuntimeStep::SynchronizeFilter));
                    ready_reported = true;
                }
            }
            else if (observer != nullptr)
            {
                observer->report_filter_progress();
                observer->report_ready(WorkerReadyResult{WorkerReadyOutcome::Ready, std::nullopt});
                ready_reported = true;

                while (!result)
                {
                    const auto action = observer->await_activation(stop_token);
                    if (action == WorkerRunObserver::GateAction::RefreshFilter)
                    {
                        if (!refresh_filter_snapshot())
                        {
                            result.emplace(fatal_exit(WorkerRuntimeStep::SynchronizeFilter));
                            break;
                        }
                        observer->report_filter_progress();
                        continue;
                    }
                    if (action == WorkerRunObserver::GateAction::Stop)
                    {
                        result.emplace(stop_token.stop_requested() ? requested_stop() : fatal_exit(WorkerRuntimeStep::AwaitActivation));
                        break;
                    }
                    if (stop_token.stop_requested())
                    {
                        result.emplace(requested_stop());
                        break;
                    }

                    observer->report_activated();
                    while (!result)
                    {
                        const auto data_action = observer->await_data_plane(stop_token);
                        if (data_action == WorkerRunObserver::GateAction::RefreshFilter)
                        {
                            if (!refresh_filter_snapshot())
                            {
                                result.emplace(fatal_exit(WorkerRuntimeStep::SynchronizeFilter));
                                break;
                            }
                            observer->report_filter_progress();
                            continue;
                        }
                        if (data_action == WorkerRunObserver::GateAction::Stop)
                        {
                            result.emplace(stop_token.stop_requested() ? requested_stop() : fatal_exit(WorkerRuntimeStep::AwaitActivation));
                            break;
                        }
                        if (stop_token.stop_requested())
                            result.emplace(requested_stop());
                        else
                            activated = true;
                        break;
                    }
                    break;
                }
            }
            else if (stop_token.stop_requested())
            {
                result.emplace(requested_stop());
            }
            else
            {
                // A null observer is the standalone/test path and activates
                // immediately after runtime initialization.
                activated = true;
            }

            if (activated)
            {
                while (!stop_token.stop_requested())
                {
                    const int timeout = (listener_pending_ || upstream_pending_ || scheduler_.has_ready())
                                            ? 0
                                            : timer_queue_.wait_timeout(runtime::TimerQueue::Clock::now());
                    const int ready   = ::epoll_wait(epoll_fd_.get(), events.data(), static_cast<int>(events.size()), timeout);
                    if (ready < 0)
                    {
                        if (errno == EINTR)
                            continue;
                        result.emplace(fatal_exit(WorkerRuntimeStep::WaitForEvents, errno));
                        break;
                    }

                    for (int index = 0; index < ready; ++index)
                    {
                        const auto kind = static_cast<EventKind>(events[static_cast<size_t>(index)].data.u64);
                        if (kind == EventKind::Wake)
                        {
                            drain_wakeup();
                            continue;
                        }
                        if (kind == EventKind::Generation)
                        {
                            drain_generation_wakeup();
                            generation_pending_ = true;
                            continue;
                        }
                        if (kind == EventKind::Listener)
                            listener_pending_ = true;
                        if (kind == EventKind::Upstream)
                        {
                            const uint32_t flags = events[static_cast<size_t>(index)].events;
                            upstream_pending_    = true;
                            upstream_error_pending_ |= (flags & EPOLLERR) != 0;
                            upstream_hangup_pending_ |= (flags & EPOLLHUP) != 0;
                        }
                    }

                    if (stop_token.stop_requested())
                        break;
                    if (generation_pending_)
                    {
                        generation_pending_ = false;
                        if (!refresh_filter_snapshot())
                        {
                            result.emplace(fatal_exit(WorkerRuntimeStep::SynchronizeFilter));
                            break;
                        }
                        if (observer != nullptr)
                            observer->report_filter_progress();
                    }
                    if (listener_pending_)
                        drain_listener(stop_token);
                    if (upstream_pending_)
                    {
                        const auto drained = upstream_channel_.drain(kUpstreamReceiveBudget);
                        upstream_pending_  = drained.has_more;
                    }
                    if (upstream_error_pending_ || upstream_hangup_pending_)
                    {
                        const bool hangup       = upstream_hangup_pending_;
                        int        socket_error = 0;
                        socklen_t  error_length = sizeof(socket_error);
                        if (::getsockopt(upstream_fd_.get(), SOL_SOCKET, SO_ERROR, &socket_error, &error_length) < 0)
                            socket_error = errno;
                        if (socket_error == 0 && upstream_hangup_pending_)
                            socket_error = ECONNRESET;

                        upstream_error_pending_  = false;
                        upstream_hangup_pending_ = false;
                        if (socket_error != 0)
                            static_cast<void>(upstream_channel_.fail_all(dns::upstream::QueryOutcome::SocketError, socket_error));
                        if (hangup)
                        {
                            upstream_usable_  = false;
                            upstream_pending_ = false;
                            upstream_fd_.reset();
                        }
                    }

                    const auto expired = timer_queue_.expire(runtime::TimerQueue::Clock::now(), kTimerBudget);
                    static_cast<void>(scheduler_.run_ready(kReadyBudget));
                    if (scheduler_.unhandled_root_exceptions() != 0)
                    {
                        result.emplace(fatal_exit(WorkerRuntimeStep::UnhandledException));
                        break;
                    }
                    if (expired.schedule_failures != 0 || !runtime_invariants_hold())
                    {
                        result.emplace(fatal_exit(WorkerRuntimeStep::RuntimeInvariant));
                        break;
                    }
                }

                if (!result)
                    result.emplace(stop_token.stop_requested() ? requested_stop() : fatal_exit(WorkerRuntimeStep::UnhandledException));
            }
        }
    }
    catch (...)
    {
        const WorkerRuntimeError error{WorkerRuntimeStep::UnhandledException, 0};
        if (!ready_reported && observer != nullptr)
            observer->report_ready(WorkerReadyResult{WorkerReadyOutcome::InitError, error});
        result.emplace(WorkerRunResult{WorkerRunOutcome::FatalExit, error});
    }

    // Every path, including partial initialization and observer failure, joins
    // here. Keeping cleanup outside the branches prevents double cancellation
    // and ensures borrowed timer/upstream nodes are released before return.
    // An exited instance must leave the SO_REUSEPORT group before completion
    // is reported; otherwise clients can be routed to a dead listener while
    // C observes the failure and schedules recovery.
    listen_fd_.reset();
    const bool shutdown_clean = shutdown_runtime();
    capture_runtime_stats();

    WorkerRunResult final_result = result.value_or(fatal_exit(WorkerRuntimeStep::UnhandledException));
    if (final_result.outcome != WorkerRunOutcome::FatalExit)
    {
        if (scheduler_.unhandled_root_exceptions() != 0)
            final_result = fatal_exit(WorkerRuntimeStep::UnhandledException);
        else if (!runtime_invariants_hold())
            final_result = fatal_exit(WorkerRuntimeStep::RuntimeInvariant);
        else if (!shutdown_clean)
            final_result = fatal_exit(WorkerRuntimeStep::Shutdown);
    }
    return final_result;
}

bool WorkerLoop::shutdown_runtime() noexcept
{
    // close() rejects new roots but deliberately leaves schedule() available,
    // allowing cancelled timer waiters to enter the ready queue and unwind.
    bool clean = scheduler_.close();
    clean      = upstream_channel_.close() && clean;
    clean      = timer_queue_.close() && clean;
    static_cast<void>(upstream_channel_.cancel_all());
    const auto cancelled = timer_queue_.cancel_all();
    clean                = cancelled.schedule_failures == 0 && clean;
    static_cast<void>(scheduler_.shutdown(kShutdownResumeBudget));
    clean = upstream_channel_.stop() && clean;
    clean = timer_queue_.stop() && clean;
    return clean;
}

void WorkerLoop::capture_runtime_stats() noexcept
{
    const auto &upstream_stats          = upstream_channel_.stats();
    stats_.upstream_queries             = upstream_stats.queries_sent;
    stats_.upstream_responses           = upstream_stats.responses_completed;
    stats_.upstream_timeouts            = upstream_stats.timeouts;
    stats_.upstream_cancellations       = upstream_stats.cancellations;
    stats_.upstream_send_errors         = upstream_stats.send_errors;
    stats_.upstream_socket_errors       = upstream_stats.socket_errors;
    stats_.upstream_overloaded          = upstream_stats.overloaded;
    stats_.upstream_invalid_responses   = upstream_stats.invalid_responses;
    stats_.upstream_unmatched_responses = upstream_stats.unmatched_responses;
    stats_.internal_errors += static_cast<uint64_t>(scheduler_.unhandled_root_exceptions() + scheduler_.invariant_failures() +
                                                    timer_queue_.invariant_failures() + upstream_stats.invariant_failures);
}

bool WorkerLoop::runtime_invariants_hold() const noexcept
{
    return scheduler_.invariant_failures() == 0 && timer_queue_.invariant_failures() == 0 && upstream_channel_.stats().invariant_failures == 0;
}

void WorkerLoop::request_stop() const noexcept
{
    static_cast<void>(stop_source_.request_stop());
    if (!wake_fd_)
        return;

    const uint64_t value = 1;
    ssize_t        result;
    do
    {
        result = ::write(wake_fd_.get(), &value, sizeof(value));
    } while (result < 0 && errno == EINTR);
}

bool WorkerLoop::request_filter_refresh() const noexcept
{
    if (!generation_fd_)
        return false;

    const uint64_t value = 1;
    ssize_t        result;
    do
    {
        result = ::write(generation_fd_.get(), &value, sizeof(value));
    } while (result < 0 && errno == EINTR);
    // EAGAIN means the eventfd counter is already readable; the outstanding
    // wake therefore still covers the latest published generation.
    return result == static_cast<ssize_t>(sizeof(value)) || (result < 0 && errno == EAGAIN);
}

void WorkerLoop::drain_wakeup() const noexcept
{
    uint64_t value{0};
    while (::read(wake_fd_.get(), &value, sizeof(value)) < 0 && errno == EINTR)
    {
    }
}

void WorkerLoop::drain_generation_wakeup() const noexcept
{
    uint64_t value{0};
    while (::read(generation_fd_.get(), &value, sizeof(value)) < 0 && errno == EINTR)
    {
    }
}

bool WorkerLoop::refresh_filter_snapshot() noexcept
{
    if (filter_publication_ == nullptr)
        return true;
    if (epoch_ == nullptr || instance_id_ == 0)
        return false;
    return filter_publication_->refresh_worker_snapshot(local_filter_snapshot_, instance_id_, *epoch_);
}

bool WorkerLoop::matches_filter(const protocol::DomainName &name) const noexcept
{
    // This helper is deliberately synchronous and only returns a value. No
    // tree node/reference can escape across the later upstream co_await.
    return local_filter_snapshot_ && local_filter_snapshot_->blocklist.matches(name);
}

void WorkerLoop::drain_listener(std::stop_token stop_token) noexcept
{
    std::array<std::byte, protocol::kDownstreamReceiveBufferSize> buffer{};
    size_t                                                        datagrams = 0;

    while (!stop_token.stop_requested() && datagrams < kReceiveBudget)
    {
        sockaddr_storage client_address{};
        iovec            io_vector{buffer.data(), buffer.size()};
        msghdr           message{};
        message.msg_name    = &client_address;
        message.msg_namelen = sizeof(client_address);
        message.msg_iov     = &io_vector;
        message.msg_iovlen  = 1;

        const ssize_t received = ::recvmsg(listen_fd_.get(), &message, MSG_TRUNC);
        if (received < 0)
        {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                listener_pending_ = false;
                return;
            }
            std::cerr << "worker " << worker_id_ << " recvmsg failed: " << std::strerror(errno) << '\n';
            listener_pending_ = false;
            return;
        }

        ++stats_.received_datagrams;
        ++datagrams;
        const bool   truncated = (message.msg_flags & MSG_TRUNC) != 0 || static_cast<size_t>(received) > buffer.size();
        const size_t available = std::min(static_cast<size_t>(received), buffer.size());
        try
        {
            ClientDatagram datagram;
            datagram.packet.assign(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(available));
            datagram.client_address = client_address;
            datagram.client_length  = std::min(message.msg_namelen, static_cast<socklen_t>(sizeof(sockaddr_storage)));
            datagram.truncated      = truncated;

            auto       task    = process_datagram(std::move(datagram));
            const auto spawned = scheduler_.spawn(std::move(task));
            if (spawned != runtime::Scheduler::SpawnResult::Spawned && !stop_token.stop_requested())
                ++stats_.internal_errors;
        }
        catch (const std::exception &error)
        {
            ++stats_.internal_errors;
            std::cerr << "worker " << worker_id_ << " failed to own datagram: " << error.what() << '\n';
        }
    }

    listener_pending_ = !stop_token.stop_requested();
}

runtime::Task<void> WorkerLoop::process_datagram(ClientDatagram datagram)
{
    try
    {
        const auto stop_token = co_await runtime::this_coro::stop_token();
        if (stop_token.stop_requested())
            co_return;

        DatagramDecision decision = evaluate_datagram(datagram.packet, datagram.truncated);
        switch (decision.outcome)
        {
            case DatagramOutcome::Dropped:
                co_return;
            case DatagramOutcome::Truncated:
                ++stats_.truncated_datagrams;
                break;
            case DatagramOutcome::Malformed:
                ++stats_.parse_errors;
                break;
            case DatagramOutcome::Unsupported:
                ++stats_.unsupported_queries;
                break;
            case DatagramOutcome::Accepted:
                ++stats_.accepted_queries;
                break;
            case DatagramOutcome::InternalError:
                ++stats_.internal_errors;
                co_return;
        }

        if (decision.outcome == DatagramOutcome::Accepted)
        {
            if (!decision.request || decision.request->questions.size() != 1)
            {
                ++stats_.internal_errors;
                co_return;
            }

            const protocol::Question &question = decision.request->questions.front();
            if (matches_filter(question.name))
            {
                ++stats_.blocked_queries;
                auto refused =
                    protocol::make_error_response(*decision.request, protocol::ResponseCode::Refused, true, protocol::kDownstreamResponseBudget);
                if (!refused)
                {
                    ++stats_.internal_errors;
                    co_return;
                }
                decision.response = std::move(*refused);
            }

            if (decision.response.empty())
            {
                const bool cache_eligible =
                    cache_shard_.capacity() != 0 && !decision.request->header.authenticated_data && !decision.request->header.checking_disabled;
                std::optional<Cache::CacheKey> cache_key;
                if (cache_eligible)
                {
                    cache_key.emplace(question.name, question.type, question.question_class);
                    auto cache_hit = cache_shard_.get(*cache_key, Cache::Clock::now());
                    if (cache_hit)
                    {
                        auto response = make_cache_hit_response(*decision.request, *cache_hit, protocol::kDownstreamResponseBudget);
                        if (response)
                        {
                            ++stats_.cache_hits;
                            decision.response = std::move(*response);
                        }
                        else if (response.error().code == protocol::WriteErrorCode::MessageTooLarge)
                        {
                            // A compressed upstream RRset can fit in 512 bytes
                            // even when this cache's canonical reconstruction
                            // cannot. Treat the entry as a miss and forward the
                            // original request exactly once.
                            ++stats_.cache_misses;
                        }
                        else
                        {
                            ++stats_.internal_errors;
                            co_return;
                        }
                    }
                    else
                    {
                        ++stats_.cache_misses;
                    }
                }
                else
                {
                    ++stats_.cache_bypasses;
                }

                if (decision.response.empty() && upstream_usable_)
                {
                    auto upstream_result = co_await upstream_channel_.query(decision.request->header, question);
                    if (upstream_result.outcome == dns::upstream::QueryOutcome::Response)
                    {
                        decision.response = std::move(upstream_result.response);
                        if (cache_key)
                        {
                            try
                            {
                                auto parsed_response = protocol::parse_message(decision.response);
                                if (parsed_response)
                                {
                                    auto cacheable = cacheable_address_set(*parsed_response, question);
                                    if (cacheable)
                                    {
                                        Cache::CacheHit candidate{std::move(cacheable->addresses), cacheable->ttl};
                                        auto cache_wire = make_cache_hit_response(*decision.request, candidate, protocol::kDownstreamResponseBudget);
                                        if (cache_wire)
                                        {
                                            cache_shard_.put(std::move(*cache_key), std::move(candidate.addresses), candidate.remaining_ttl,
                                                             Cache::Clock::now());
                                            ++stats_.cache_inserts;
                                        }
                                    }
                                }
                            }
                            catch (const std::exception &error)
                            {
                                ++stats_.internal_errors;
                                std::cerr << "worker " << worker_id_ << " could not cache an upstream response: " << error.what() << '\n';
                            }
                        }
                    }
                }
            }
            if (decision.response.empty())
            {
                auto servfail =
                    protocol::make_error_response(*decision.request, protocol::ResponseCode::ServFail, true, protocol::kDownstreamResponseBudget);
                if (!servfail)
                {
                    ++stats_.internal_errors;
                    co_return;
                }
                decision.response = std::move(*servfail);
            }
        }

        if (!decision.response.empty() && !stop_token.stop_requested())
            send_response(decision.response, reinterpret_cast<const sockaddr *>(&datagram.client_address), datagram.client_length);
    }
    catch (const runtime::OperationCancelled &)
    {
    }
    catch (const std::exception &error)
    {
        ++stats_.internal_errors;
        std::cerr << "worker " << worker_id_ << " failed to process datagram: " << error.what() << '\n';
    }
    co_return;
}

void WorkerLoop::send_response(const std::vector<std::byte> &response, const sockaddr *client_address, socklen_t client_length) noexcept
{
    if (response.size() > protocol::kDownstreamResponseBudget)
    {
        ++stats_.oversized_responses;
        std::cerr << "worker " << worker_id_ << " refused to send an oversized downstream response (" << response.size() << " bytes)\n";
        return;
    }

    ssize_t sent;
    do
    {
        sent = ::sendto(listen_fd_.get(), response.data(), response.size(), 0, client_address, client_length);
    } while (sent < 0 && errno == EINTR);

    if (sent == static_cast<ssize_t>(response.size()))
        ++stats_.responses_sent;
    else
    {
        ++stats_.send_errors;
        std::cerr << "worker " << worker_id_ << " sendto failed: " << std::strerror(errno) << '\n';
    }
}

} // namespace dns::server
