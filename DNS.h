#pragma once

#include "CuckooFilter.h"
#include "RadixTree.h"
#include "DNS_Cache.h"
#include "WorkerContext.h"
#include <atomic>
#include <cstdint>
#include <memory>
#include <thread>
#include <vector>

struct FilterContext
{
    std::unique_ptr<Filter::CuckooFilter> cuckoo;
    std::unique_ptr<RadixTree>            trie;

    FilterContext()
        : cuckoo(std::make_unique<Filter::CuckooFilter>())
        , trie(std::make_unique<RadixTree>())
    {
    }
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
    std::atomic<std::shared_ptr<FilterContext>> active_context{nullptr};
    std::atomic<std::shared_ptr<FilterContext>> update_context{nullptr};
    std::unique_ptr<Cache::DNS_Cache>           cache{nullptr};
    std::vector<std::jthread>                   worker_threads;
    std::vector<std::jthread>                   manager_threads;
    size_t                                      worker_count{0};
    size_t                                      manager_count{0};
    uint16_t                                    port{0};
};