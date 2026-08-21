#include "protocol/DnsLimits.h"
#include "protocol/DnsParser.h"
#include "protocol/DnsWriter.h"
#include "runtime/Scheduler.h"
#include "runtime/Task.h"
#include "runtime/TimerQueue.h"
#include "runtime/UniqueFd.h"
#include "tests/SocketTestSupport.h"
#include "upstream/UpstreamChannel.h"

#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <sys/socket.h>
#include <thread>
#include <utility>
#include <vector>

namespace
{

using dns::runtime::Scheduler;
using dns::runtime::Task;
using dns::runtime::TimerQueue;
using dns::upstream::ChannelConfig;
using dns::upstream::QueryOutcome;
using dns::upstream::QueryResult;
using dns::upstream::UpstreamChannel;
using namespace std::chrono_literals;

void require(bool condition, std::string_view message)
{
    if (condition)
        return;
    std::cerr << "upstream test failed: " << message << '\n';
    std::exit(EXIT_FAILURE);
}

void require_spawned(Scheduler::SpawnResult result, std::string_view message)
{
    require(result == Scheduler::SpawnResult::Spawned, message);
}

dns::protocol::Question make_question(std::string_view text, dns::protocol::RecordType type = dns::protocol::RecordType::A)
{
    auto name = dns::protocol::DomainName::from_text(text);
    require(name.has_value(), "upstream fixture domain must be valid");
    return dns::protocol::Question{std::move(*name), static_cast<uint16_t>(type), static_cast<uint16_t>(dns::protocol::RecordClass::IN)};
}

dns::protocol::Header make_header(uint16_t client_id)
{
    dns::protocol::Header header;
    header.id                = client_id;
    header.recursion_desired = true;
    return header;
}

struct QueryObservation
{
    std::optional<QueryResult> result;
    size_t                     completions{0};
    bool                       cancelled{false};
};

Task<void> observe_query(UpstreamChannel &channel, dns::protocol::Header header, dns::protocol::Question question, TimerQueue::TimePoint deadline,
                         QueryObservation &observation)
{
    try
    {
        observation.result.emplace(co_await channel.query_until(std::move(header), std::move(question), deadline));
    }
    catch (const dns::runtime::OperationCancelled &)
    {
        observation.cancelled = true;
    }
    ++observation.completions;
}

class LoopbackFixture final
{
public:
    struct Datagram
    {
        std::vector<std::byte> packet;
    };

    explicit LoopbackFixture(size_t transaction_id_capacity = 64, TimerQueue::Duration query_timeout = 1s, TimerQueue::Duration id_reuse_guard = 1s)
    {
        int sockets[2]{-1, -1};
        require(::socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sockets) == 0, "connected datagram fixture must be created");
        upstream_socket_.reset(sockets[0]);
        channel_socket_.reset(sockets[1]);

        require(scheduler_.start(), "fixture Scheduler must start");
        require(timers_.start(scheduler_), "fixture TimerQueue must start");

        ChannelConfig config;
        config.query_timeout             = query_timeout;
        config.id_reuse_guard            = id_reuse_guard;
        config.transaction_id_capacity   = transaction_id_capacity;
        config.initial_transaction_id    = 7;
        config.randomize_transaction_ids = false;
        require(channel_.start(channel_socket_.get(), scheduler_, timers_, config), "fixture UpstreamChannel must start");
    }

    LoopbackFixture(const LoopbackFixture &)            = delete;
    LoopbackFixture &operator=(const LoopbackFixture &) = delete;

    Datagram receive_query()
    {
        std::array<std::byte, dns::protocol::kUpstreamReceiveBufferSize> buffer{};
        Datagram                                                     datagram;
        const ssize_t received = ::recv(upstream_socket_.get(), buffer.data(), buffer.size(), 0);
        if (received <= 0)
        {
            std::cerr << "fake upstream receive failed, errno=" << errno << '\n';
            require(false, "UpstreamChannel must send a UDP query before the watchdog expires");
        }
        datagram.packet.assign(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(received));
        return datagram;
    }

    void send_response(const Datagram &, std::span<const std::byte> response)
    {
        const ssize_t sent = ::send(upstream_socket_.get(), response.data(), response.size(), 0);
        require(sent == static_cast<ssize_t>(response.size()), "fake upstream must send the complete UDP response");
    }

    void shutdown()
    {
        require(scheduler_.close(), "fixture Scheduler must close on its owner thread");
        require(channel_.close(), "fixture UpstreamChannel must close on its owner thread");
        static_cast<void>(channel_.cancel_all());
        require(timers_.close(), "fixture TimerQueue must close on its owner thread");
        static_cast<void>(timers_.cancel_all());
        static_cast<void>(scheduler_.shutdown());
        require(channel_.pending_count() == 0 && channel_.stop(), "empty UpstreamChannel must stop after frame cleanup");
        require(timers_.empty() && timers_.stop(), "empty TimerQueue must stop after frame cleanup");
        require(channel_.stats().invariant_failures == 0 && timers_.invariant_failures() == 0 && scheduler_.invariant_failures() == 0 &&
                    scheduler_.unhandled_root_exceptions() == 0,
                "fixture shutdown must not report runtime invariants or unhandled exceptions");
    }

    [[nodiscard]] Scheduler       &scheduler() noexcept { return scheduler_; }
    [[nodiscard]] TimerQueue      &timers() noexcept { return timers_; }
    [[nodiscard]] UpstreamChannel &channel() noexcept { return channel_; }

private:
    // Sockets and TimerQueue outlive channel-owned coroutine frames. Scheduler
    // is declared last so its destructor is the first ownership fallback.
    dns::runtime::UniqueFd upstream_socket_;
    dns::runtime::UniqueFd channel_socket_;
    TimerQueue             timers_;
    UpstreamChannel        channel_;
    Scheduler              scheduler_;
};

std::vector<std::byte> make_valid_response(std::span<const std::byte> forwarded_query)
{
    auto request = dns::protocol::parse_message(forwarded_query);
    require(request.has_value(), "forwarded query must remain parseable");
    auto response = dns::protocol::make_error_response(*request, dns::protocol::ResponseCode::NoError);
    require(response.has_value(), "fake upstream response must serialize");
    return std::move(*response);
}

std::vector<std::byte> make_wrong_question_response(std::span<const std::byte> forwarded_query)
{
    auto request = dns::protocol::parse_message(forwarded_query);
    require(request.has_value() && request->questions.size() == 1, "invalid-response fixture query must parse");
    request->questions.front() = make_question("wrong.example");
    auto response              = dns::protocol::make_error_response(*request, dns::protocol::ResponseCode::NoError);
    require(response.has_value(), "invalid-response fixture must serialize");
    return std::move(*response);
}

std::vector<std::byte> make_valid_response_of_size(std::span<const std::byte> forwarded_query, size_t target_size)
{
    auto response = make_valid_response(forwarded_query);

    // Append one private-use RR with a root owner. Its RDATA is intentionally
    // opaque, so the fixture can produce every wire size while remaining a
    // syntactically valid classic DNS response.
    constexpr size_t additional_envelope_size = 11;
    require(response.size() + additional_envelope_size <= target_size, "sized response fixture must have room for an additional RR");
    const size_t rdata_size = target_size - response.size() - additional_envelope_size;
    require(rdata_size <= 65'535, "sized response fixture RDATA must fit RDLENGTH");
    response[10] = std::byte{0};
    response[11] = std::byte{1};
    response.push_back(std::byte{0});        // root owner
    response.push_back(std::byte{0xff});
    response.push_back(std::byte{0x00});     // private-use type 65280
    response.push_back(std::byte{0});
    response.push_back(std::byte{1});        // IN
    response.insert(response.end(), 4, std::byte{0}); // TTL
    response.push_back(static_cast<std::byte>((rdata_size >> 8U) & 0xffU));
    response.push_back(static_cast<std::byte>(rdata_size & 0xffU));
    response.insert(response.end(), rdata_size, std::byte{0x5a});
    require(response.size() == target_size && dns::protocol::parse_message(response).has_value(),
            "sized response fixture must remain a valid DNS message");
    return response;
}

std::vector<dns::protocol::Question> make_exact_size_questions(size_t label_size)
{
    auto root = dns::protocol::DomainName::from_text(".");
    require(root.has_value(), "root question fixture must be valid");

    std::vector<dns::protocol::Question> questions;
    questions.reserve(99);
    for (size_t index = 0; index < 98; ++index)
        questions.push_back(dns::protocol::Question{*root, static_cast<uint16_t>(dns::protocol::RecordType::A),
                                                    static_cast<uint16_t>(dns::protocol::RecordClass::IN)});
    questions.push_back(make_question(std::string(label_size, 'a')));
    return questions;
}

void test_query_serializer_with_upstream_budget()
{
    const auto header = make_header(0x1122);

    auto wire_511 = dns::protocol::serialize_query(header, make_exact_size_questions(3), dns::protocol::kUpstreamQueryBudget);
    require(wire_511 && wire_511->size() == 511, "the query serializer must accept 511 bytes under the upstream budget");

    auto wire_512 = dns::protocol::serialize_query(header, make_exact_size_questions(4), dns::protocol::kUpstreamQueryBudget);
    require(wire_512 && wire_512->size() == dns::protocol::kClassicDnsUdpPayloadLimit,
            "the query serializer must accept exactly 512 bytes under the upstream budget");

    auto wire_513 = dns::protocol::serialize_query(header, make_exact_size_questions(5), dns::protocol::kUpstreamQueryBudget);
    require(!wire_513 && wire_513.error().code == dns::protocol::WriteErrorCode::MessageTooLarge,
            "the query serializer must reject 513 bytes under the upstream budget");
}

void test_success_restores_client_id()
{
    LoopbackFixture    fixture;
    QueryObservation   observation;
    const auto         question  = make_question("success.example");
    constexpr uint16_t client_id = 0xbeef;

    require_spawned(
        fixture.scheduler().spawn(observe_query(fixture.channel(), make_header(client_id), question, TimerQueue::TimePoint::max(), observation)),
        "successful upstream query must spawn");
    require(fixture.scheduler().run_ready(1).resumed == 1 && fixture.channel().pending_count() == 1 && fixture.timers().size() == 1,
            "first coroutine turn must send and arm the upstream query");

    const auto request        = fixture.receive_query();
    auto       parsed_request = dns::protocol::parse_message(request.packet);
    require(parsed_request && parsed_request->header.id == 7 && parsed_request->header.id != client_id &&
                parsed_request->questions == std::vector<dns::protocol::Question>{question},
            "forwarding must replace the client ID while preserving the question");

    const auto response = make_valid_response(request.packet);
    fixture.send_response(request, response);
    const auto drained = fixture.channel().drain(8);
    require(drained.datagrams == 1 && !drained.socket_error && fixture.channel().pending_count() == 0 && fixture.timers().empty() &&
                fixture.scheduler().ready_count() == 1 && observation.completions == 0,
            "a valid UDP response must enqueue, not inline-resume, its waiter");
    require(fixture.scheduler().run_ready(1).resumed == 1 && observation.completions == 1 && observation.result &&
                observation.result->outcome == QueryOutcome::Response,
            "the scheduled waiter must observe a successful response exactly once");

    auto restored = dns::protocol::parse_message(observation.result->response);
    require(restored && restored->header.id == client_id && restored->header.is_response && restored->questions.size() == 1 &&
                restored->questions.front() == question,
            "the completed response must restore the original client ID and question");
    require(fixture.channel().stats().queries_sent == 1 && fixture.channel().stats().responses_completed == 1,
            "successful exchange statistics must be exact");
    fixture.shutdown();
}

void test_timeout_ignores_late_response()
{
    LoopbackFixture  fixture;
    QueryObservation observation;
    const auto       deadline = TimerQueue::TimePoint{} + 10s;

    require_spawned(
        fixture.scheduler().spawn(observe_query(fixture.channel(), make_header(0x1234), make_question("late.example"), deadline, observation)),
        "timeout query must spawn");
    require(fixture.scheduler().run_ready(1).resumed == 1 && fixture.channel().pending_count() == 1, "timeout query must become pending");
    const auto request       = fixture.receive_query();
    const auto late_response = make_valid_response(request.packet);

    const auto expired = fixture.timers().expire(deadline);
    require(expired.dispatched == 1 && expired.schedule_failures == 0 && fixture.channel().pending_count() == 0 &&
                fixture.scheduler().ready_count() == 1 && observation.completions == 0,
            "deadline expiry must detach and enqueue the pending query once");
    require(fixture.scheduler().run_ready(1).resumed == 1 && observation.completions == 1 && observation.result &&
                observation.result->outcome == QueryOutcome::Timeout,
            "expired query must resume with Timeout exactly once");

    fixture.send_response(request, late_response);
    const auto drained = fixture.channel().drain(8);
    require(drained.datagrams == 1 && fixture.channel().stats().unmatched_responses == 1 && !fixture.scheduler().has_ready() &&
                observation.completions == 1 && fixture.channel().stats().responses_completed == 0,
            "a response arriving after timeout must be unmatched and must not complete again");
    fixture.shutdown();
}

void test_invalid_then_valid_response()
{
    LoopbackFixture  fixture;
    QueryObservation observation;
    const auto       question = make_question("validation.example");

    require_spawned(
        fixture.scheduler().spawn(observe_query(fixture.channel(), make_header(0x5678), question, TimerQueue::TimePoint::max(), observation)),
        "response-validation query must spawn");
    require(fixture.scheduler().run_ready(1).resumed == 1 && fixture.channel().pending_count() == 1, "response-validation query must become pending");
    const auto request = fixture.receive_query();

    const auto invalid = make_wrong_question_response(request.packet);
    fixture.send_response(request, invalid);
    auto drained = fixture.channel().drain(8);
    require(drained.datagrams == 1 && fixture.channel().stats().invalid_responses == 1 && fixture.channel().pending_count() == 1 &&
                fixture.timers().size() == 1 && !fixture.scheduler().has_ready() && observation.completions == 0,
            "an invalid response must leave the original query armed and suspended");

    const auto valid = make_valid_response(request.packet);
    fixture.send_response(request, valid);
    drained = fixture.channel().drain(8);
    require(drained.datagrams == 1 && fixture.channel().pending_count() == 0 && fixture.scheduler().ready_count() == 1,
            "a subsequent valid response must still complete the pending query");
    require(fixture.scheduler().run_ready(1).resumed == 1 && observation.completions == 1 && observation.result &&
                observation.result->outcome == QueryOutcome::Response,
            "valid response after an invalid packet must resume exactly once");
    fixture.shutdown();
}

void test_classic_udp_response_boundary()
{
    LoopbackFixture fixture;

    for (const size_t response_size : {size_t{511}, dns::protocol::kClassicDnsUdpPayloadLimit})
    {
        QueryObservation observation;
        const auto       question = make_question(response_size == 511 ? "response-511.example" : "response-512.example");
        require_spawned(fixture.scheduler().spawn(
                            observe_query(fixture.channel(), make_header(static_cast<uint16_t>(response_size)), question,
                                          TimerQueue::TimePoint::max(), observation)),
                        "boundary response query must spawn");
        require(fixture.scheduler().run_ready(1).resumed == 1 && fixture.channel().pending_count() == 1,
                "boundary response query must become pending");

        const auto request  = fixture.receive_query();
        const auto response = make_valid_response_of_size(request.packet, response_size);
        fixture.send_response(request, response);
        const auto drained = fixture.channel().drain(1);
        require(drained.datagrams == 1 && !drained.socket_error && fixture.channel().pending_count() == 0 &&
                    fixture.scheduler().ready_count() == 1,
                "a response at or below 512 bytes must complete its pending query");
        require(fixture.scheduler().run_ready(1).resumed == 1 && observation.completions == 1 && observation.result &&
                    observation.result->outcome == QueryOutcome::Response && observation.result->response.size() == response_size,
                "the complete 511/512-byte upstream response must be returned without truncation");
    }

    require(fixture.channel().stats().responses_completed == 2 && fixture.channel().stats().invalid_responses == 0,
            "both accepted boundary responses must be counted exactly");
    fixture.shutdown();
}

void test_oversized_response_keeps_waiter_for_later_valid_response()
{
    LoopbackFixture  fixture;
    QueryObservation observation;
    const auto       question = make_question("oversized-then-valid.example");

    require_spawned(fixture.scheduler().spawn(
                        observe_query(fixture.channel(), make_header(0x5130), question, TimerQueue::TimePoint::max(), observation)),
                    "oversized-then-valid query must spawn");
    require(fixture.scheduler().run_ready(1).resumed == 1 && fixture.channel().pending_count() == 1,
            "oversized-then-valid query must become pending");
    const auto request = fixture.receive_query();

    const auto oversized = make_valid_response_of_size(request.packet, dns::protocol::kClassicDnsUdpPayloadLimit + 1);
    fixture.send_response(request, oversized);
    auto drained = fixture.channel().drain(1);
    require(drained.datagrams == 1 && !drained.socket_error && fixture.channel().stats().invalid_responses == 1 &&
                fixture.channel().pending_count() == 1 && fixture.timers().size() == 1 && !fixture.scheduler().has_ready() &&
                observation.completions == 0,
            "a 513-byte upstream response must be discarded without failing or resuming its waiter");

    const auto valid = make_valid_response(request.packet);
    fixture.send_response(request, valid);
    drained = fixture.channel().drain(1);
    require(drained.datagrams == 1 && fixture.channel().pending_count() == 0 && fixture.scheduler().ready_count() == 1,
            "a valid response after an oversized datagram must still match the pending query");
    require(fixture.scheduler().run_ready(1).resumed == 1 && observation.completions == 1 && observation.result &&
                observation.result->outcome == QueryOutcome::Response,
            "the later valid response must complete exactly once");
    fixture.shutdown();
}

void test_oversized_response_eventually_times_out()
{
    LoopbackFixture  fixture;
    QueryObservation observation;
    const auto       deadline = TimerQueue::TimePoint{} + 20s;

    require_spawned(fixture.scheduler().spawn(observe_query(fixture.channel(), make_header(0x5131),
                                                            make_question("oversized-timeout.example"), deadline, observation)),
                    "oversized-timeout query must spawn");
    require(fixture.scheduler().run_ready(1).resumed == 1 && fixture.channel().pending_count() == 1,
            "oversized-timeout query must become pending");
    const auto request   = fixture.receive_query();
    const auto oversized = make_valid_response_of_size(request.packet, dns::protocol::kClassicDnsUdpPayloadLimit + 1);
    fixture.send_response(request, oversized);
    require(fixture.channel().drain(1).datagrams == 1 && fixture.channel().pending_count() == 1 &&
                fixture.channel().stats().invalid_responses == 1 && !fixture.scheduler().has_ready(),
            "an oversized response must leave the deadline armed");

    const auto expired = fixture.timers().expire(deadline);
    require(expired.dispatched == 1 && expired.schedule_failures == 0 && fixture.channel().pending_count() == 0 &&
                fixture.scheduler().ready_count() == 1,
            "the unchanged waiter must follow the ordinary timeout path");
    require(fixture.scheduler().run_ready(1).resumed == 1 && observation.completions == 1 && observation.result &&
                observation.result->outcome == QueryOutcome::Timeout && fixture.channel().stats().timeouts == 1,
            "oversized input alone must eventually produce Timeout rather than an immediate socket failure");
    fixture.shutdown();
}

void test_out_of_order_responses_match_their_waiters()
{
    LoopbackFixture  fixture;
    QueryObservation first;
    QueryObservation second;
    const auto       first_question  = make_question("first.order.example");
    const auto       second_question = make_question("second.order.example");

    require_spawned(
        fixture.scheduler().spawn(observe_query(fixture.channel(), make_header(0x1010), first_question, TimerQueue::TimePoint::max(), first)),
        "first out-of-order query must spawn");
    require_spawned(
        fixture.scheduler().spawn(observe_query(fixture.channel(), make_header(0x2020), second_question, TimerQueue::TimePoint::max(), second)),
        "second out-of-order query must spawn");
    require(fixture.scheduler().run_ready(2).resumed == 2 && fixture.channel().pending_count() == 2, "both out-of-order queries must become pending");

    const auto first_request  = fixture.receive_query();
    const auto second_request = fixture.receive_query();
    fixture.send_response(second_request, make_valid_response(second_request.packet));
    fixture.send_response(first_request, make_valid_response(first_request.packet));
    require(fixture.channel().drain(8).datagrams == 2 && fixture.channel().pending_count() == 0 && fixture.scheduler().ready_count() == 2,
            "reverse-order packets must enqueue both matching waiters");
    require(fixture.scheduler().run_ready(2).resumed == 2 && first.completions == 1 && second.completions == 1 && first.result && second.result &&
                first.result->outcome == QueryOutcome::Response && second.result->outcome == QueryOutcome::Response,
            "each out-of-order waiter must complete exactly once");

    const auto first_response  = dns::protocol::parse_message(first.result->response);
    const auto second_response = dns::protocol::parse_message(second.result->response);
    require(first_response && first_response->header.id == 0x1010 && first_response->questions.front() == first_question && second_response &&
                second_response->header.id == 0x2020 && second_response->questions.front() == second_question,
            "reverse arrival must not swap client IDs or questions");
    fixture.shutdown();
}

void test_completed_id_is_quarantined()
{
    LoopbackFixture  fixture{1, 1h, 1h};
    QueryObservation first;
    const auto       question = make_question("guard.example");

    require_spawned(fixture.scheduler().spawn(observe_query(fixture.channel(), make_header(0x1111), question, TimerQueue::TimePoint::max(), first)),
                    "guarded-ID query must spawn");
    require(fixture.scheduler().run_ready(1).resumed == 1, "guarded-ID query must send");
    const auto request  = fixture.receive_query();
    const auto response = make_valid_response(request.packet);
    fixture.send_response(request, response);
    require(fixture.channel().drain(8).datagrams == 1 && fixture.scheduler().run_ready(1).resumed == 1 && first.result &&
                first.result->outcome == QueryOutcome::Response,
            "first guarded-ID query must complete successfully");

    QueryObservation second;
    require_spawned(fixture.scheduler().spawn(observe_query(fixture.channel(), make_header(0x2222), question, TimerQueue::TimePoint::max(), second)),
                    "query competing with a quarantined ID must spawn");
    require(fixture.scheduler().run_ready(1).resumed == 1 && second.completions == 1 && second.result &&
                second.result->outcome == QueryOutcome::Overloaded && fixture.channel().pending_count() == 0 && fixture.timers().empty(),
            "a one-ID namespace must reject reuse until its guard expires");

    fixture.send_response(request, response);
    require(fixture.channel().drain(8).datagrams == 1 && fixture.channel().stats().unmatched_responses == 1 &&
                fixture.channel().stats().queries_sent == 1 && fixture.channel().stats().overloaded == 1 && second.completions == 1,
            "a duplicate response inside the guard must remain unmatched and cannot resume another coroutine");
    fixture.shutdown();
}

void test_cancel_all()
{
    LoopbackFixture  fixture;
    QueryObservation first;
    QueryObservation second;

    require_spawned(fixture.scheduler().spawn(observe_query(fixture.channel(), make_header(0x1111), make_question("first.cancel.example"),
                                                            TimerQueue::TimePoint::max(), first)),
                    "first cancellation query must spawn");
    require_spawned(fixture.scheduler().spawn(observe_query(fixture.channel(), make_header(0x2222), make_question("second.cancel.example"),
                                                            TimerQueue::TimePoint::max(), second)),
                    "second cancellation query must spawn");
    require(fixture.scheduler().run_ready(2).resumed == 2 && fixture.channel().pending_count() == 2 && fixture.timers().size() == 2,
            "both cancellation queries must become pending");
    static_cast<void>(fixture.receive_query());
    static_cast<void>(fixture.receive_query());

    require(fixture.channel().cancel_all() == 2 && fixture.channel().pending_count() == 0 && fixture.timers().empty() &&
                fixture.scheduler().ready_count() == 2 && first.completions == 0 && second.completions == 0,
            "cancel_all must detach every query and enqueue both waiters");
    require(fixture.scheduler().run_ready(2).resumed == 2 && first.completions == 1 && second.completions == 1 && first.cancelled &&
                second.cancelled && !first.result && !second.result,
            "cancelled queries must unwind once through OperationCancelled");
    require(fixture.channel().cancel_all() == 0 && !fixture.scheduler().has_ready() && fixture.channel().stats().cancellations == 2,
            "repeated cancel_all must be idempotent");
    fixture.shutdown();
}

void test_owner_thread_destruction_cancels_pending_query()
{
    int sockets[2]{-1, -1};
    require(::socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sockets) == 0,
            "destructor connected datagram fixture must be created");
    dns::runtime::UniqueFd fake_socket{sockets[0]};
    dns::runtime::UniqueFd channel_socket{sockets[1]};

    Scheduler  scheduler;
    TimerQueue timers;
    require(scheduler.start() && timers.start(scheduler), "destructor runtime fixture must start");

    ChannelConfig config;
    config.query_timeout             = 1s;
    config.id_reuse_guard            = 1s;
    config.transaction_id_capacity   = 4;
    config.initial_transaction_id    = 0;
    config.randomize_transaction_ids = false;
    auto channel                     = std::make_unique<UpstreamChannel>();
    require(channel->start(channel_socket.get(), scheduler, timers, config), "destructor UpstreamChannel fixture must start");

    QueryObservation observation;
    require_spawned(
        scheduler.spawn(observe_query(*channel, make_header(0x3333), make_question("destroy.example"), TimerQueue::TimePoint::max(), observation)),
        "query pending during channel destruction must spawn");
    require(scheduler.run_ready(1).resumed == 1 && channel->pending_count() == 1 && timers.size() == 1,
            "destructor query must be pending before channel destruction");
    std::array<std::byte, dns::protocol::kUpstreamReceiveBufferSize> sent_query{};
    require(::recv(fake_socket.get(), sent_query.data(), sent_query.size(), 0) > 0, "destructor query must reach its connected peer");

    channel.reset();
    require(timers.empty() && scheduler.ready_count() == 1 && observation.completions == 0,
            "owner-thread channel destruction must disarm and enqueue its pending waiter");
    require(scheduler.run_ready(1).resumed == 1 && observation.completions == 1 && observation.cancelled && !observation.result,
            "a waiter cancelled by channel destruction must unwind exactly once");

    require(scheduler.close() && timers.close(), "destructor runtime fixture must close cleanly");
    static_cast<void>(timers.cancel_all());
    static_cast<void>(scheduler.shutdown());
    require(timers.stop() && scheduler.invariant_failures() == 0 && timers.invariant_failures() == 0,
            "destructor runtime fixture must stop without invariants");
}

void test_restart_discards_stale_socket_input()
{
    int sockets[2]{-1, -1};
    require(::socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sockets) == 0, "restart connected datagram fixture must be created");
    dns::runtime::UniqueFd fake_socket{sockets[0]};
    dns::runtime::UniqueFd channel_socket{sockets[1]};

    Scheduler       scheduler;
    TimerQueue      timers;
    UpstreamChannel channel;
    ChannelConfig   config;
    config.query_timeout             = 1ms;
    config.id_reuse_guard            = 1ms;
    config.transaction_id_capacity   = 1;
    config.initial_transaction_id    = 0;
    config.randomize_transaction_ids = false;

    require(scheduler.start() && timers.start(scheduler) && channel.start(channel_socket.get(), scheduler, timers, config),
            "first restart cycle must start");
    QueryObservation first;
    const auto       question = make_question("restart.example");
    require_spawned(scheduler.spawn(observe_query(channel, make_header(0x4444), question, TimerQueue::TimePoint::max(), first)),
                    "first restart-cycle query must spawn");
    require(scheduler.run_ready(1).resumed == 1, "first restart-cycle query must send");

    std::array<std::byte, dns::protocol::kUpstreamReceiveBufferSize> buffer{};
    const ssize_t                                              first_size = ::recv(fake_socket.get(), buffer.data(), buffer.size(), 0);
    require(first_size > 0, "first restart-cycle query must reach its peer");
    const auto stale_response = make_valid_response(std::span<const std::byte>{buffer}.first(static_cast<size_t>(first_size)));

    require(channel.close() && channel.cancel_all() == 1 && timers.close() && timers.empty(),
            "first restart cycle must cancel and detach its pending query");
    require(scheduler.close(), "first restart-cycle Scheduler must close");
    require(scheduler.shutdown() == 1 && first.cancelled && first.completions == 1, "first restart-cycle waiter must unwind through cancellation");
    require(channel.stop() && timers.stop(), "first restart cycle must stop cleanly");

    std::this_thread::sleep_for(10ms);
    require(::send(fake_socket.get(), stale_response.data(), stale_response.size(), 0) == static_cast<ssize_t>(stale_response.size()),
            "a stale response must be queued while the channel is stopped");

    require(scheduler.start() && timers.start(scheduler) && channel.start(channel_socket.get(), scheduler, timers, config),
            "second restart cycle must start and discard queued input");
    require(channel.drain(8).datagrams == 0, "channel restart must drain stale datagrams before accepting new queries");

    QueryObservation second;
    require_spawned(scheduler.spawn(observe_query(channel, make_header(0x5555), question, TimerQueue::TimePoint::max(), second)),
                    "second restart-cycle query must spawn");
    require(scheduler.run_ready(1).resumed == 1 && channel.pending_count() == 1,
            "second restart-cycle query must reuse the now-safe one-ID namespace");
    const ssize_t second_size = ::recv(fake_socket.get(), buffer.data(), buffer.size(), 0);
    require(second_size > 0, "second restart-cycle query must reach its peer");
    const auto current_response = make_valid_response(std::span<const std::byte>{buffer}.first(static_cast<size_t>(second_size)));
    require(::send(fake_socket.get(), current_response.data(), current_response.size(), 0) == static_cast<ssize_t>(current_response.size()),
            "current restart-cycle response must be sent");
    require(channel.drain(8).datagrams == 1 && scheduler.run_ready(1).resumed == 1 && second.result &&
                second.result->outcome == QueryOutcome::Response && second.completions == 1,
            "only the current response may complete the restarted query");

    require(scheduler.close() && channel.close() && timers.close(), "second restart cycle must close cleanly");
    static_cast<void>(channel.cancel_all());
    static_cast<void>(timers.cancel_all());
    static_cast<void>(scheduler.shutdown());
    require(channel.stop() && timers.stop() && scheduler.invariant_failures() == 0 && timers.invariant_failures() == 0 &&
                channel.stats().invariant_failures == 0,
            "second restart cycle must stop without invariants");
}

} // namespace

int main()
{
    const auto socket_capability = dns::test::probe_unix_datagram_io();
    if (!socket_capability.available)
        return dns::test::socket_test_unavailable_exit(socket_capability, "upstream channel tests");

    test_query_serializer_with_upstream_budget();
    test_success_restores_client_id();
    test_timeout_ignores_late_response();
    test_invalid_then_valid_response();
    test_classic_udp_response_boundary();
    test_oversized_response_keeps_waiter_for_later_valid_response();
    test_oversized_response_eventually_times_out();
    test_out_of_order_responses_match_their_waiters();
    test_completed_id_is_quarantined();
    test_cancel_all();
    test_owner_thread_destruction_cancels_pending_query();
    test_restart_discards_stale_socket_input();
    std::cout << "all upstream channel tests passed\n";
    return EXIT_SUCCESS;
}
