#include <iostream>
#include <vector>
#include <chrono>
#include <string>
#include <random>
#include <cstring>
#include <nmmintrin.h> // SSE4.2 硬件指令集头文件
#define XXH_INLINE_ALL
#include <xxhash.h>



// 模拟你原始代码中的常量
const size_t MAX_DOMAIN_LEN = 256;

// --- 方案 A: 你原始的 MurmurHash 实现 ---
size_t original_murMurHash(const unsigned char *key, size_t len)
{
    const unsigned int m    = 0x5bd1e995;
    const int          r    = 24;
    const int          seed = 97;
    unsigned int       h    = seed ^ len;
    while (len >= 4)
    {
        unsigned int k;
        memcpy(&k, key, 4);
        k *= m;
        k ^= k >> r;
        k *= m;
        h *= m;
        h ^= k;
        key += 4;
        len -= 4;
    }
    switch (len)
    {
        case 3:
            h ^= key[2] << 16;
            [[fallthrough]];
        case 2:
            h ^= key[1] << 8;
            [[fallthrough]];
        case 1:
            h ^= key[0];
            h *= m;
    };
    h ^= h >> 13;
    h *= m;
    h ^= h >> 15;
    return h;
}

// --- 方案 B: 硬件加速的 CRC32 实现 ---
size_t hardware_crc32(const unsigned char *data, size_t len)
{
    uint64_t crc = 0; // 种子
    // 每次步进 8 字节
    while (len >= 8)
    {
        crc = _mm_crc32_u64(crc, *reinterpret_cast<const uint64_t *>(data));
        data += 8;
        len -= 8;
    }
    // 处理剩余字节
    if (len >= 4)
    {
        crc = _mm_crc32_u32(crc, *reinterpret_cast<const uint32_t *>(data));
        data += 4;
        len -= 4;
    }
    if (len >= 2)
    {
        crc = _mm_crc32_u16(crc, *reinterpret_cast<const uint16_t *>(data));
        data += 2;
        len -= 2;
    }
    if (len == 1)
    {
        crc = _mm_crc32_u8(crc, *data);
    }
    return crc;
}

int main()
{
    const int                       num_tests = 10'000'000;
    std::vector<std::string>        test_domains;
    std::mt19937                    gen(42);
    std::uniform_int_distribution<> dis(10, 60); // 模拟常见域名长度

    // 准备测试数据
    for (int i = 0; i < num_tests; ++i)
    {
        std::string s(dis(gen), 'a');
        test_domains.push_back(s);
    }

    std::cout << "start calculating hash values of " << num_tests << " domains" << std::endl;

    // 测试 MurmurHash
    auto   start = std::chrono::high_resolution_clock::now();
    size_t sum1  = 0;
    for (const auto &d : test_domains)
    {
        sum1 += original_murMurHash(reinterpret_cast<const unsigned char *>(d.data()), d.size());
    }
    auto                                      end   = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> diff1 = end - start;
    std::cout << "Original MurmurHash: " << diff1.count() << " ms (crc_sum: " << sum1 << ")" << std::endl;

    // 测试 Hardware CRC32
    start       = std::chrono::high_resolution_clock::now();
    size_t sum2 = 0;
    for (const auto &d : test_domains)
    {
        sum2 += hardware_crc32(reinterpret_cast<const unsigned char *>(d.data()), d.size());
    }
    end                                             = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> diff2 = end - start;
    std::cout << "Hardware CRC32:      " << diff2.count() << " ms (crc_sum: " << sum2 << ")" << std::endl;

    // 测试 XXH3_64
    start       = std::chrono::high_resolution_clock::now();
    size_t sum3 = 0;
    for (const auto &d : test_domains)
    {
        sum3 += XXH3_64bits(reinterpret_cast<const unsigned char *>(d.data()), d.size());
    }
    end                                             = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> diff3 = end - start;
    std::cout << "XXH3_64:             " << diff3.count() << " ms (crc_sum: " << sum3 << ")" << std::endl;

    std::cout << "\n CRC32 vs MurmurHash speed ratio: " << diff1.count() / diff2.count() << "x" << std::endl;
    std::cout << " XXH3_64 vs MurmurHash speed ratio: " << diff1.count() / diff3.count() << "x" << std::endl;
    std::cout << " XXH3_64 vs CRC32 speed ratio: " << diff2.count() / diff3.count() << "x" << std::endl;

    return 0;
}