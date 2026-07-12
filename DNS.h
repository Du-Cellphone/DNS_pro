#pragma once

#include "DomainBlocklist.h"
#include "DNS_Cache.h"
#include "WorkerContext.h"
#include <atomic>
#include <cstdint>
#include <memory>
#include <thread>
#include <vector>

struct FilterContext
{
    Filter::DomainBlocklist blocklist;
};

class DNS
{
public:
    bool init(size_t worker_thread_cnt, size_t manager_thread_cnt);
    void start();

private:
    bool init_network_env(WorkerContext &ctx, uint16_t port);
    void worker();
    void manager();

private:
    std::atomic<std::shared_ptr<const FilterContext>> active_context{nullptr};
    std::unique_ptr<Cache::DNS_Cache>                 cache{nullptr};
    std::vector<std::jthread>                   worker_threads;
    std::vector<std::jthread>                   manager_threads;
    size_t                                      worker_count{0};
    size_t                                      manager_count{0};
    uint16_t                                    port{0};
};
