#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <random>
#include <string>
#include <string_view>
#include <vector>

#include <nmmintrin.h> // SSE4.2 CRC32
#define XXH_INLINE_ALL
#include <xxhash.h>

// 安全版本：避免未对齐 reinterpret_cast 导致 UB
static inline uint64_t crc32_hw(std::string_view sv) noexcept
{
    const char *data = sv.data();
    size_t      len  = sv.size();
    uint64_t    crc  = 0;

    while (len >= 8)
    {
        uint64_t v;
        std::memcpy(&v, data, sizeof(v));
        crc = _mm_crc32_u64(crc, v);
        data += 8;
        len -= 8;
    }
    while (len >= 4)
    {
        uint32_t v;
        std::memcpy(&v, data, sizeof(v));
        crc = _mm_crc32_u32(static_cast<uint32_t>(crc), v);
        data += 4;
        len -= 4;
    }
    while (len >= 2)
    {
        uint16_t v;
        std::memcpy(&v, data, sizeof(v));
        crc = _mm_crc32_u16(static_cast<uint32_t>(crc), v);
        data += 2;
        len -= 2;
    }
    if (len)
    {
        crc = _mm_crc32_u8(static_cast<uint32_t>(crc), static_cast<uint8_t>(*data));
    }
    return crc;
}

static inline uint64_t xxh3_64(std::string_view sv) noexcept
{
    return XXH3_64bits(sv.data(), sv.size());
}

static std::vector<std::string> make_domains(size_t n)
{
    std::array<const char *, 20> tlds = {"com", "net", "org", "io", "co", "ru", "cn", "de", "uk", "fr",
                                         "jp",  "br",  "au",  "in", "ca", "mx", "es", "it", "nl", "se"};

    std::vector<std::string> out;
    out.reserve(n);

    // 分布尽量接近真实：短域名 + 子域名 + 较长域名
    for (size_t i = 0; i < n; ++i)
    {
        const char *tld = tlds[i % tlds.size()];
        if (i % 10 < 5)
        {
            out.emplace_back("domain" + std::to_string(i) + "." + tld);
        }
        else if (i % 10 < 8)
        {
            out.emplace_back("sub" + std::to_string(i % 100) + ".domain" + std::to_string(i / 3) + "." + tld);
        }
        else
        {
            out.emplace_back("svc" + std::to_string(i % 7) + ".edge" + std::to_string(i % 31) + ".sub" + std::to_string(i % 17) + ".domain" +
                             std::to_string(i / 11) + "." + tld);
        }
    }

    // 打乱访问顺序，避免顺序数据的 cache 偏置
    std::mt19937_64 rng(42);
    std::shuffle(out.begin(), out.end(), rng);
    return out;
}

template <typename HashFn>
static void run_bench(const char *name, const std::vector<std::string> &data, HashFn &&fn, int rounds = 5)
{
    constexpr size_t  kWarmupIters = 200000;
    volatile uint64_t sink         = 0;

    // warmup
    for (size_t i = 0; i < kWarmupIters; ++i)
    {
        const auto &s = data[i % data.size()];
        sink ^= fn(std::string_view{s});
    }

    double       best_ms = 1e100;
    double       sum_ms  = 0.0;
    const size_t n       = data.size();

    for (int r = 0; r < rounds; ++r)
    {
        auto t0 = std::chrono::high_resolution_clock::now();
        for (size_t i = 0; i < n; ++i)
        {
            sink ^= fn(std::string_view{data[i]});
        }
        auto   t1 = std::chrono::high_resolution_clock::now();
        double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        best_ms   = std::min(best_ms, ms);
        sum_ms += ms;
    }

    double avg_ms    = sum_ms / rounds;
    double ns_per_op = (avg_ms * 1e6) / static_cast<double>(n);
    double mops      = static_cast<double>(n) / (avg_ms / 1000.0) / 1e6;

    size_t total_bytes = 0;
    for (const auto &s : data)
        total_bytes += s.size();
    double gbps = (static_cast<double>(total_bytes) / (1024.0 * 1024.0 * 1024.0)) / (avg_ms / 1000.0);

    std::cout << std::left << std::setw(14) << name << " avg: " << std::setw(9) << avg_ms << " ms"
              << " best: " << std::setw(9) << best_ms << " ms"
              << " ns/op: " << std::setw(9) << ns_per_op << " Mops/s: " << std::setw(9) << mops << " GiB/s: " << gbps << "\n";

    // 防止优化
    if (sink == 0xdeadbeefULL)
    {
        std::cerr << "ignore: " << sink << "\n";
    }
}

int main()
{
    const size_t N       = 1'000'000;
    auto         domains = make_domains(N);

    size_t avg_len = 0;
    for (const auto &s : domains)
        avg_len += s.size();
    avg_len /= domains.size();

    std::cout << "samples: " << domains.size() << ", avg_len: " << avg_len << "\n";

    run_bench("CRC32_hw", domains, [](std::string_view sv) { return crc32_hw(sv); });
    run_bench("XXH3_64", domains, [](std::string_view sv) { return xxh3_64(sv); });

    return 0;
}