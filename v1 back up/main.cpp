#include "DNS_Cache.h"
#include <cstdlib>
#include <iostream>
#include <memory>
#include <vector>
#include <thread>
#include <random>
#include <atomic>
#include <string>

// 模拟 10 万个不同域名池
const int DOMAIN_POOL_SIZE = 100'000;
const int OPS_PER_THREAD   = 5000000;

std::vector<std::string> generate_domains()
{
    std::vector<std::string> domains;
    domains.reserve(DOMAIN_POOL_SIZE);
    for (int i = 0; i < DOMAIN_POOL_SIZE; ++i)
    {
        domains.push_back("www.testdomain" + std::to_string(i) + ".com");
    }
    return domains;
}

void worker_thread(DNS_Cache &cache, const std::vector<std::string> &domains, int thread_id, std::atomic<int> &hits, std::atomic<int> &misses)
{
    // 每个线程有自己的随机数生成器
    std::mt19937                       rng(thread_id + 42);
    std::uniform_int_distribution<int> dist(0, DOMAIN_POOL_SIZE - 1);

    int local_hits   = 0;
    int local_misses = 0;

    std::vector<unsigned char> dummy_ip = {192, 168, 1, static_cast<unsigned char>(thread_id % 255)};

    for (int i = 0; i < OPS_PER_THREAD; ++i)
    {
        auto               now           = std::chrono::high_resolution_clock::now();
        const std::string &target_domain = domains[dist(rng)];

        // 模拟真实查询：先查 Cache
        auto result = cache.get(target_domain, now);

        if (result.has_value())
        {
            local_hits++;
        }
        else
        {
            local_misses++;
            // Cache Miss: 模拟向权威 DNS 查询后，写入 Cache
            cache.put(target_domain, dummy_ip, now);
        }
    }

    hits += local_hits;
    misses += local_misses;
}

int main()
{
    std::cout << "Initializing Domain Pool..." << std::endl;
    auto domains = generate_domains();

    std::cout << "Initializing DNS Cache (Shards: " << SHARD_CNT << ")..." << std::endl;
    DNS_Cache cache;

    int                      num_threads = SHARD_CNT; // 使用硬件并发数
    std::vector<std::thread> threads;
    std::atomic<int>         total_hits{0};
    std::atomic<int>         total_misses{0};

    std::cout << "Starting " << num_threads << " threads. Each doing " << OPS_PER_THREAD << " ops..." << std::endl;

    auto start_time = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < num_threads; ++i)
    {
        threads.emplace_back(worker_thread, std::ref(cache), std::ref(domains), i, std::ref(total_hits), std::ref(total_misses));
    }

    for (auto &t : threads)
    {
        // std::cout << "starting thread " << t.get_id() << '\n';
        t.join();
    }

    auto                          end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diff     = end_time - start_time;

    long long total_ops = num_threads * OPS_PER_THREAD;

    std::cout << "-----------------------------------" << std::endl;
    std::cout << "Benchmark Completed in: " << diff.count() << " seconds\n";
    std::cout << "Total Operations:       " << total_ops << "\n";
    std::cout << "Throughput:             " << (total_ops / diff.count()) / 1000000.0 << " Million Ops/sec\n";
    std::cout << "Cache Hits:             " << total_hits << "\n";
    std::cout << "Cache Misses (Writes):  " << total_misses << "\n";
    std::cout << "Hit Rate:               " << (total_hits.load() * 100.0 / total_ops) << "%\n";
    std::cout << "-----------------------------------" << std::endl;

    // system("pause");
    return 0;
}