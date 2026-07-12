#include "CuckooFilter.h"

#include "HashUtils.hpp"

#include <algorithm>
#include <bit>
#include <limits>
#include <stdexcept>

namespace Filter
{
namespace
{

size_t normalize_bucket_count(size_t requested)
{
    requested = std::max<size_t>(requested, 4);
    constexpr size_t maximum_power_of_two = size_t{1} << (std::numeric_limits<size_t>::digits - 1);
    if (requested > maximum_power_of_two)
        throw std::length_error("CuckooFilter bucket count is too large");
    return std::bit_ceil(requested);
}

size_t load_limit(size_t total_slots) noexcept
{
    return (total_slots / 100) * 95 + ((total_slots % 100) * 95) / 100;
}

} // namespace

CuckooFilter::CuckooFilter(size_t requested_bucket_count, size_t maximum_kicks)
    : maximum_kicks_(maximum_kicks)
{
    const size_t bucket_count = normalize_bucket_count(requested_bucket_count);
    if (bucket_count > buckets_.max_size() || bucket_count > std::numeric_limits<size_t>::max() / FPS_PER_BUCKET)
        throw std::length_error("CuckooFilter capacity overflows size_t");
    buckets_.resize(bucket_count);
    rng_state_ = splitmix64(static_cast<uint64_t>(buckets_.size()) ^ 0xD1B54A32D192ED03ULL);
}

bool CuckooFilter::insert(std::string_view item)
{
    last_failure_ = InsertFailureReason::None;
    const uint64_t    hash = xxH3_64bits(item);
    const Fingerprint fingerprint = calc_fp(hash);
    const size_t      index1 = static_cast<size_t>(hash) & (buckets_.size() - 1);

    if (find_fp(index1, fingerprint))
        return true;

    const size_t total_slots = buckets_.size() * FPS_PER_BUCKET;
    if (size_ >= load_limit(total_slots))
    {
        last_failure_ = InsertFailureReason::LoadLimit;
        return false;
    }

    if (auto empty_slot = find_empty_slot(index1))
    {
        buckets_[index1].fingerprints[*empty_slot] = fingerprint;
        ++size_;
        return true;
    }

    const size_t index2 = alternate_index(index1, fingerprint);
    if (auto empty_slot = find_empty_slot(index2))
    {
        buckets_[index2].fingerprints[*empty_slot] = fingerprint;
        ++size_;
        return true;
    }

    const uint64_t rng_before = rng_state_;
    const size_t victim_index = (next_rand_u64() & 1ULL) == 0 ? index1 : index2;
    if (kick_out(victim_index, fingerprint))
        return true;

    rng_state_ = rng_before;
    last_failure_ = InsertFailureReason::KickLimit;
    return false;
}

bool CuckooFilter::contains(std::string_view item) const noexcept
{
    const uint64_t    hash = xxH3_64bits(item);
    const Fingerprint fingerprint = calc_fp(hash);
    const size_t      index = static_cast<size_t>(hash) & (buckets_.size() - 1);
    return find_fp(index, fingerprint);
}

bool CuckooFilter::find_fp(size_t index, const Fingerprint &fingerprint) const noexcept
{
    const auto contains_in_bucket = [&](size_t bucket_index) {
        const auto &slots = buckets_[bucket_index].fingerprints;
        return std::find(slots.begin(), slots.end(), fingerprint) != slots.end();
    };
    return contains_in_bucket(index) || contains_in_bucket(alternate_index(index, fingerprint));
}

std::optional<size_t> CuckooFilter::find_empty_slot(size_t index) const noexcept
{
    const auto &slots = buckets_[index].fingerprints;
    for (size_t slot = 0; slot < slots.size(); ++slot)
    {
        if (slots[slot].none())
            return slot;
    }
    return std::nullopt;
}

bool CuckooFilter::kick_out(size_t victim_index, Fingerprint fingerprint)
{
    std::vector<KickRecord> history;
    history.reserve(maximum_kicks_);

    for (size_t kick = 0; kick < maximum_kicks_; ++kick)
    {
        const size_t slot = static_cast<size_t>(next_rand_u64() % FPS_PER_BUCKET);
        Fingerprint &victim = buckets_[victim_index].fingerprints[slot];
        history.push_back(KickRecord{victim_index, slot, victim});
        std::swap(victim, fingerprint);

        victim_index = alternate_index(victim_index, fingerprint);
        if (auto empty_slot = find_empty_slot(victim_index))
        {
            buckets_[victim_index].fingerprints[*empty_slot] = fingerprint;
            ++size_;
            return true;
        }
    }

    for (auto record = history.rbegin(); record != history.rend(); ++record)
        buckets_[record->bucket_index].fingerprints[record->slot_index] = record->previous;
    return false;
}

Fingerprint CuckooFilter::calc_fp(uint64_t hash) const noexcept
{
    const uint16_t high16bits = static_cast<uint16_t>(hash >> (64 - FINGERPRINT_LEN));
    return Fingerprint{high16bits % MAX_FINGERPRINT_VALUE + 1};
}

uint64_t CuckooFilter::splitmix64(uint64_t value) const noexcept
{
    value += 0x9e3779b97f4a7c15ULL;
    value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ULL;
    value = (value ^ (value >> 27)) * 0x94d049bb133111ebULL;
    return value ^ (value >> 31);
}

size_t CuckooFilter::alternate_index(size_t index, const Fingerprint &fingerprint) const noexcept
{
    const size_t mask = buckets_.size() - 1;
    size_t delta = static_cast<size_t>(splitmix64(fingerprint.to_ullong())) & mask;
    if (delta == 0)
        delta = 1;
    return index ^ delta;
}

uint64_t CuckooFilter::next_rand_u64() noexcept
{
    rng_state_ += 0x9e3779b97f4a7c15ULL;
    return splitmix64(rng_state_);
}

} // namespace Filter
