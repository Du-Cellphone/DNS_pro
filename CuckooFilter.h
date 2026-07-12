#pragma once

#include <array>
#include <bitset>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace Filter
{

inline constexpr size_t MAX_KICKS          = 500;
inline constexpr size_t DEFAULT_TABLE_SIZE = 1ULL << 20;
inline constexpr size_t FINGERPRINT_LEN    = 16;
inline constexpr size_t FPS_PER_BUCKET     = 4;
inline constexpr size_t MAX_FINGERPRINT_VALUE = (1ULL << FINGERPRINT_LEN) - 1;

using Fingerprint = std::bitset<FINGERPRINT_LEN>;

enum class InsertFailureReason
{
    None,
    LoadLimit,
    KickLimit,
};

class CuckooFilter final
{
public:
    explicit CuckooFilter(size_t requested_bucket_count = DEFAULT_TABLE_SIZE, size_t maximum_kicks = MAX_KICKS);

    [[nodiscard]] bool   contains(std::string_view item) const noexcept;
    [[nodiscard]] size_t get_size() const noexcept { return size_; }
    [[nodiscard]] size_t bucket_count() const noexcept { return buckets_.size(); }
    [[nodiscard]] InsertFailureReason last_failure() const noexcept { return last_failure_; }

    // A false result provides the strong guarantee: all existing fingerprints
    // and the PRNG state remain unchanged.
    bool insert(std::string_view item);

private:
    struct Bucket
    {
        std::array<Fingerprint, FPS_PER_BUCKET> fingerprints;
    };

    struct KickRecord
    {
        size_t      bucket_index;
        size_t      slot_index;
        Fingerprint previous;
    };

    [[nodiscard]] bool find_fp(size_t index, const Fingerprint &fingerprint) const noexcept;
    std::optional<size_t> find_empty_slot(size_t index) const noexcept;
    bool                  kick_out(size_t victim_index, Fingerprint fingerprint);

    [[nodiscard]] Fingerprint calc_fp(uint64_t hash) const noexcept;
    [[nodiscard]] uint64_t    splitmix64(uint64_t value) const noexcept;
    [[nodiscard]] size_t      alternate_index(size_t index, const Fingerprint &fingerprint) const noexcept;
    uint64_t                  next_rand_u64() noexcept;

    std::vector<Bucket> buckets_;
    size_t              size_{0};
    size_t              maximum_kicks_{MAX_KICKS};
    uint64_t            rng_state_{0};
    InsertFailureReason last_failure_{InsertFailureReason::None};
};

} // namespace Filter
