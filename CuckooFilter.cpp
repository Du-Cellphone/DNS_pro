#include "CuckooFilter.h"
#include <cassert>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string_view>


namespace Filter
{
CuckooFilter::CuckooFilter(size_t cap)
    : capacity(std::bit_ceil(cap < 4 ? 4 : cap)) // 确保容量是2的幂次方
{
    assert(capacity >= 4);
    assert((capacity & (capacity - 1)) == 0); // 确保capacity是2的幂次方
    table.assign(capacity, Bucket{});

    rng_state = splitmix64(static_cast<uint64_t>(capacity) ^ 0xD1B54A32D192ED03ULL); // 初始化随机数生成器状态

    while (!build_table())
    {
        if (capacity == SIZE_MAX)
            throw std::runtime_error("CuckooFilter: Reached maximum capacity, cannot build filter");

        capacity = capacity * 2 > SIZE_MAX ? SIZE_MAX : capacity * 2;
        table.assign(capacity, Bucket{});
        size      = 0;
        rng_state = splitmix64(rng_state ^ static_cast<uint64_t>(capacity));
    }
}

bool CuckooFilter::build_table(/*could be databse or file input*/)
{
    // 实际构建逻辑后续接数据库或文件加载。
    // 当前保持空表初始化，调用方在基准或业务代码中通过循环 insert() 构建过滤器。
    return true;
}

bool CuckooFilter::insert(const std::string_view &item)
{
    uint64_t    hash = xxH3_64bits(item);
    Fingerprint fp{calc_fp(hash)};

    size_t index1 = static_cast<size_t>(hash) & (capacity - 1);
    if (find_fp(index1, fp))
        return true; // 已存在，无需插入

    // 插入前检查负载，如果过高则拒绝插入以避免性能急剧下降
    const uint64_t limit = (static_cast<uint64_t>(capacity) * static_cast<uint64_t>(FPS_PER_BUCKET) * 95ULL) / 100ULL; // 95%负载上限
    if (static_cast<uint64_t>(size) + 1ULL > limit)
        return false;

    if (auto empty_slot = find_empty_slot(index1))
    {
        empty_slot->get() = fp;
        size++;
        return true;
    }
    size_t index2 = alter_index(index1, fp);
    if (auto empty_slot = find_empty_slot(index2))
    {
        empty_slot->get() = fp;
        size++;
        return true;
    }

    // 随机一个桶
    size_t victim_idx = ((next_rand_u64() & 1ULL) == 0ULL) ? index1 : index2;

    return kick_out(victim_idx, fp); // 可能会失败，返回false表示插入失败
}

bool CuckooFilter::contains(const std::string_view &item) const
{
    uint64_t hash = xxH3_64bits(item);
    // 使用高16位作为指纹，且确保指纹不为0，因为0表示空槽
    Fingerprint fp{calc_fp(hash)};

    size_t index1 = static_cast<size_t>(hash) & (capacity - 1); // 计算第一个桶的索引，使用位运算代替取模，前提是capacity必须是2的幂次方

    return find_fp(index1, fp);
}

// 只读查找
bool CuckooFilter::find_fp(const size_t index1, const Fingerprint &fp) const
{
    const Bucket &b1 = table[index1];
    for (const Fingerprint &f : b1.fingerprints)
    {
        if (f == fp)
            return true;
    }

    // 第一个桶没找到，则在第二个桶接着找
    // size_t index2 = index1 ^ G(fp) G为整数混淆函数
    size_t index2 = alter_index(index1, fp);

    const Bucket &b2 = table[index2];
    for (const Fingerprint &f : b2.fingerprints)
    {
        if (f == fp)
            return true;
    }
    return false;
}


std::optional<std::reference_wrapper<Fingerprint>> CuckooFilter::find_empty_slot(const size_t index)
{
    Bucket &b1 = table[index];
    for (Fingerprint &f : b1.fingerprints)
    {
        if (f.none())
            return std::ref(f);
    }

    return std::nullopt;
}

bool CuckooFilter::kick_out(size_t victim_idx, Fingerprint &fp)
{
    size_t cnt{0};
    do
    {
        const size_t victim_fp_idx = static_cast<size_t>(next_rand_u64() % FPS_PER_BUCKET); // 随机选择一个受害者指纹槽index

        Fingerprint victim_fp                         = table[victim_idx].fingerprints[victim_fp_idx]; // 暂存
        table[victim_idx].fingerprints[victim_fp_idx] = fp;                                            // 覆盖

        const size_t victim_next_idx = alter_index(victim_idx, victim_fp);
        if (auto empty_slot = find_empty_slot(victim_next_idx))
        {
            empty_slot->get() = victim_fp;
            size++;
            return true;
        }
        // 继续踢出下一个，fp永远代表当前要插入的指纹
        fp         = victim_fp;
        victim_idx = victim_next_idx; // 下一个受害者为当前受害者的备用位置
    } while (++cnt < MAX_KICKS);

    return false;
}


Fingerprint CuckooFilter::calc_fp(const uint64_t hash) const
{
    const uint16_t high16bits = static_cast<uint16_t>((hash >> (64 - FINGERPRINT_LEN)));
    return Fingerprint{high16bits % MAX_FINGERPRINT_VALUE + 1}; // 确保指纹不为0，因为0表示空槽
}

inline uint64_t CuckooFilter::splitmix64(uint64_t x) const
{
    // 固定的“魔法”常数，都是精心挑选的
    x += 0x9e3779b97f4a7c15;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9;
    x = (x ^ (x >> 27)) * 0x94d049bb133111eb;
    x = x ^ (x >> 31);
    return x;
}

size_t CuckooFilter::alter_index(size_t index, const Fingerprint &fp) const
{
    const size_t mask  = capacity - 1;
    size_t       delta = static_cast<size_t>(splitmix64(fp.to_ullong())) & mask;
    if (delta == 0)
        delta = 1; // 确保delta不为0，否则indxe2与index1冲突
    return index ^ delta;
}

uint64_t CuckooFilter::next_rand_u64()
{
    rng_state += 0x9e3779b97f4a7c15ULL;
    return splitmix64(rng_state);
}

} // namespace Filter