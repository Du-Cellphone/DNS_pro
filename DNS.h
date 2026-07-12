#pragma once

#include "DNS_Cache.h"
#include "DomainBlocklist.h"
#include "WorkerLoop.h"

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <stop_token>
#include <thread>
#include <vector>

struct FilterContext
{
    Filter::DomainBlocklist blocklist;
};

struct DNSConfig
{
    size_t   worker_count{1};
    size_t   manager_count{1};
    size_t   cache_capacity{Cache::DEFAULT_TOTAL_CAPACITY};
    uint16_t port{5353};
};

class DNS final
{
public:
    DNS() = default;
    ~DNS();

    DNS(const DNS &) = delete;
    DNS &operator=(const DNS &) = delete;

    bool init(const DNSConfig &config);
    bool init(size_t worker_thread_count, size_t manager_thread_count);
    bool start();
    void request_stop() noexcept;
    void join() noexcept;

    [[nodiscard]] bool is_running() const noexcept;
    [[nodiscard]] std::optional<uint16_t> bound_port() const noexcept;

private:
    enum class State
    {
        Empty,
        Initialized,
        Running,
        Stopping,
        Stopped,
    };

    void manager(std::stop_token stop_token) noexcept;

    mutable std::mutex lifecycle_mutex_;
    std::condition_variable_any manager_wakeup_;
    State state_{State::Empty};
    DNSConfig config_{};

    std::atomic<std::shared_ptr<const FilterContext>> active_context_{nullptr};
    std::unique_ptr<Cache::DNS_Cache> cache_;
    std::vector<std::unique_ptr<dns::server::WorkerLoop>> worker_loops_;
    std::vector<std::jthread> worker_threads_;
    std::vector<std::jthread> manager_threads_;
};
