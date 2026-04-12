#pragma once
#include <array>
#include <bitset>
#include <cstddef>
#include <optional>
#include <vector>
#include <string_view>
#include <cstdint>
#include "HashUtils.hpp"


namespace Filter
{
constexpr size_t MAX_KICKS          = 500ULL;
constexpr size_t DEFAULT_TABLE_SIZE = 1ULL << 20; // 默认表大小为2^20
constexpr size_t FINGERPRINT_LEN    = 16ULL;      // 每个指纹16比特
constexpr size_t FPS_PER_BUCKET     = 4ULL;       // 每个桶4个指纹

// 表示对应指纹位数的最大值，方便后续使用
constexpr size_t MAX_FINGERPRINT_VALUE = (1ULL << FINGERPRINT_LEN) - 1; // 0xFFFF

using Fingerprint = std::bitset<FINGERPRINT_LEN>; // 16比特的指纹

class CuckooFilter final
{
public:
    CuckooFilter(size_t cap = DEFAULT_TABLE_SIZE);
    bool   contains(const std::string_view &item) const;
    size_t get_size() const { return this->size; };
    bool   insert(const std::string_view &item);

private:
    bool build_table(/*could be database or file input*/);


    inline bool                                               find_fp(const size_t index1, const Fingerprint &fp) const;
    inline std::optional<std::reference_wrapper<Fingerprint>> find_empty_slot(const size_t index);
    bool                                                      kick_out(size_t victim_idx, Fingerprint &fp);

    Fingerprint calc_fp(const uint64_t hash) const;
    uint64_t    splitmix64(uint64_t x) const;
    size_t      alter_index(size_t index, const Fingerprint &fp) const;
    uint64_t    next_rand_u64();

    struct Bucket
    {
        std::array<Fingerprint, FPS_PER_BUCKET> fingerprints; // 每个桶4个指纹
    };

    std::vector<Bucket> table;
    size_t              size{0};
    size_t              capacity{0};
    uint64_t            rng_state{0}; // 用于踢出过程中的伪随机数生成
};

} // namespace Filter
