// #include "DNS_Cache.h"
// #include <cstdint>
// #include <iostream>
// #include <vector>
// #include <thread>
// #include <random>
// #include <atomic>
// #include <string>
// #include <cassert>
// #include <windows.h>

// // 模拟 10 万个不同域名池
// const int DOMAIN_POOL_SIZE = 100'000;
// const int OPS_PER_THREAD   = 50'000'000;

// std::vector<std::string> generate_domains()
// {
//     std::vector<std::string> domains;
//     domains.reserve(DOMAIN_POOL_SIZE);
//     for (int i = 0; i < DOMAIN_POOL_SIZE; ++i)
//     {
//         domains.push_back("www.testdomain" + std::to_string(i) + ".com");
//     }
//     return domains;
// }

// void worker_thread(DNS_Cache &cache, const std::vector<std::string> &domains, int thread_id, std::atomic<int> &hits, std::atomic<int> &misses)
// {
//     // 每个线程有自己的随机数生成器
//     std::mt19937                       rng(thread_id + 42);
//     std::uniform_int_distribution<int> dist(0, DOMAIN_POOL_SIZE - 1);

//     int local_hits   = 0;
//     int local_misses = 0;

//     IPAddress expected_ip;

//     // SetThreadAffinityMask(GetCurrentThread(), 1ULL << thread_id);

//     cache.initialize_thread_shard(thread_id);

//     for (int i = 0; i < OPS_PER_THREAD; ++i)
//     {
//         auto               now           = std::chrono::high_resolution_clock::now();
//         const std::string &target_domain = domains[dist(rng)];
//         expected_ip.ip                   = {192, 168, 1, static_cast<uint8_t>(target_domain.length() % 255)};
//         expected_ip.len                  = 4;

//         // 模拟真实查询：先查 Cache
//         auto result = cache.get(target_domain, now);

//         if (result.has_value())
//         {
//             local_hits++;
//             assert(result.value() == expected_ip && "wrong result!!");
//         }
//         else
//         {
//             local_misses++;
//             // Cache Miss: 模拟向权威 DNS 查询后，写入 Cache
//             cache.put(target_domain, expected_ip, now);
//         }
//     }

//     hits += local_hits;
//     misses += local_misses;
// }

// int main()
// {
//     std::cout << "Initializing Domain Pool..." << std::endl;
//     auto domains = generate_domains();

//     std::cout << "Initializing DNS Cache (Shards: " << SHARD_CNT << ")..." << std::endl;
//     DNS_Cache cache;

//     int                      num_threads = SHARD_CNT; // 使用硬件并发数
//     std::vector<std::thread> threads;
//     std::atomic<int>         total_hits{0};
//     std::atomic<int>         total_misses{0};

//     std::cout << "Starting " << num_threads << " threads. Each doing " << OPS_PER_THREAD << " ops..." << std::endl;

//     auto start_time = std::chrono::high_resolution_clock::now();

//     for (int i = 0; i < num_threads; ++i)
//     {
//         threads.emplace_back(worker_thread, std::ref(cache), std::ref(domains), i, std::ref(total_hits), std::ref(total_misses));
//     }

//     for (auto &t : threads)
//     {
//         // std::cout << "starting thread " << t.get_id() << '\n';
//         // cache.initialize_thread_shard();
//         t.join();
//     }

//     auto                          end_time = std::chrono::high_resolution_clock::now();
//     std::chrono::duration<double> diff     = end_time - start_time;

//     long long total_ops = num_threads * OPS_PER_THREAD;

//     std::cout << "-----------------------------------" << std::endl;
//     std::cout << "Benchmark Completed in: " << diff.count() << " seconds\n";
//     std::cout << "Total Operations:       " << total_ops << "\n";
//     std::cout << "Throughput:             " << (total_ops / diff.count()) / 1000000.0 << " Million Ops/sec\n";
//     std::cout << "Cache Hits:             " << total_hits << "\n";
//     std::cout << "Cache Misses (Writes):  " << total_misses << "\n";
//     std::cout << "Hit Rate:               " << (total_hits.load() * 100.0 / total_ops) << "%\n";
//     std::cout << "-----------------------------------" << std::endl;

//     // system("pause");
//     return 0;
// }

// #include <atomic>
// #include <thread>
// #include <vector>
// #include <string>
// #include <iostream>
// #include <chrono>

// class CuckooFilter
// {
// public:
//     bool might_contain(const std::string &domain) const { return true; }
// };

// class RadixTree
// {
// public:
//     bool search(const std::string &domain) const { return false; }
// };

// struct FilterContext
// {
//     CuckooFilter *cuckoo;
//     RadixTree    *tree;

//     FilterContext()
//         : cuckoo(new CuckooFilter())
//         , tree(new RadixTree())
//     {
//     }
//     ~FilterContext()
//     {
//         delete cuckoo;
//         delete tree;
//     }
// };


// std::atomic<FilterContext *> g_active_context{nullptr};
// std::atomic<bool>            g_running{true};

// void worker_thread(int worker_id)
// {
//     uint64_t request_count = 0;
//     // 首次获取当前激活的名单
//     FilterContext *local_ctx = g_active_context.load(std::memory_order_acquire);

//     while (g_running.load(std::memory_order_relaxed))
//     {
//         std::string req_domain = "example.com"; // 模拟请求域名

//         if (++request_count % 1024 == 0)
//         {
//             FilterContext *latest = g_active_context.load(std::memory_order_acquire);
//             if (latest != local_ctx)
//             {
//                 local_ctx = latest;
//             }
//         }

//         if (local_ctx != nullptr && local_ctx->cuckoo->might_contain(req_domain))
//         {
//             if (local_ctx->tree->search(req_domain))
//             {
//                 // 命中黑名单，执行拦截逻辑
//             }
//         }
//     }
// }

// void manager_thread()
// {
//     while (g_running.load(std::memory_order_relaxed))
//     {
//         std::this_thread::sleep_for(std::chrono::seconds(5)); // 模拟每5秒更新一次名单
//         std::cout << "[Manager] Updating filter context...\n";

//         FilterContext *new_ctx = new FilterContext();

//         FilterContext *old_ctx = g_active_context.exchange(new_ctx, std::memory_order_acq_rel);

//         if (old_ctx != nullptr)
//         {
//             std::this_thread::sleep_for(std::chrono::milliseconds(100));
//             delete old_ctx;
//             std::cout << "[Manager] Old context deleted.\n";
//         }
//     }
// }

// int main()
// {
//     g_active_context.store(new FilterContext(), std::memory_order_release);

//     std::thread manager(manager_thread);

//     std::vector<std::thread> workers;
//     for (int i = 0; i < 15; ++i)
//     {
//         workers.emplace_back(worker_thread, i);
//     }

//     std::cout << "DNS filter running. Press Enter to stop...\n";
//     std::cin.get();

//     g_running.store(false, std::memory_order_relaxed);
//     manager.join();
//     for (auto &w : workers)
//     {
//         w.join();
//     }

//     delete g_active_context.load();
//     std::cout << "DNS filter stopped.\n";
//     return 0;
// }

#include "DNS.h"

#include <iostream>

int main()
{
    DNS dns;
    if (!dns.init(15, 1) || !dns.start())
        return 1;

    std::cin.get();
    dns.request_stop();
    dns.join();
    return 0;
}
