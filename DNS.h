#pragma once

#include "DNS_Cache.h"
#include "FilterUpdateController.h"
#include "WorkerLoop.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>

struct DNSConfig
{
    size_t   worker_count{1};
    size_t   manager_count{1};
    size_t   cache_capacity{Cache::DEFAULT_TOTAL_CAPACITY};
    uint16_t port{5353};
    // Startup input only. DNS stores the compiled immutable snapshot, not this
    // source vector.
    std::vector<std::string>    blocked_domains;
    dns::server::UpstreamConfig upstream{};
};

class DNS final
{
public:
    DNS() = default;
    ~DNS();

    DNS(const DNS &)            = delete;
    DNS &operator=(const DNS &) = delete;

    bool init(const DNSConfig &config);
    bool init(size_t worker_thread_count, size_t manager_thread_count);
    bool start();
    void request_stop() noexcept;
    void join() noexcept;

    [[nodiscard]] dns::server::FilterUpdateResult replace_blocked_domains(std::vector<std::string> rules);

    [[nodiscard]] bool                                      is_running() const noexcept;
    [[nodiscard]] std::optional<uint16_t>                   bound_port() const noexcept;
    [[nodiscard]] std::optional<dns::server::FilterVersion> filter_version() const noexcept;

private:
    enum class State
    {
        Empty,
        Initialized,
        Starting,
        Running,
        Stopping,
        Stopped,
    };

    struct RuntimeConfig
    {
        size_t                      worker_count{1};
        size_t                      manager_count{1};
        size_t                      cache_capacity{Cache::DEFAULT_TOTAL_CAPACITY};
        uint16_t                    port{5353};
        dns::server::UpstreamConfig upstream{};
    };

    void request_stop_locked() noexcept;
    void manager(std::stop_token stop_token) noexcept;

    std::mutex         join_mutex_;
    mutable std::mutex lifecycle_mutex_;
    State              state_{State::Empty};
    RuntimeConfig      config_{};

    std::unique_ptr<dns::server::FilterUpdateController>  filter_updates_;
    std::unique_ptr<Cache::DNS_Cache>                     cache_;
    std::vector<std::unique_ptr<dns::server::WorkerLoop>> worker_loops_;
    std::vector<std::jthread>                             worker_threads_;
    std::vector<std::jthread>                             manager_threads_;
};
