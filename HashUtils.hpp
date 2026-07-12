#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

#if (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
#include <nmmintrin.h>
#define DNS_PRO_HAS_TARGETED_SSE42 1
#else
#define DNS_PRO_HAS_TARGETED_SSE42 0
#endif

#define XXH_INLINE_ALL
#include "xxhash.h"

namespace HashDetail
{

#if DNS_PRO_HAS_TARGETED_SSE42

[[gnu::target("sse4.2")]] inline size_t crc32_sse42(std::string_view value) noexcept
{
    const char *data = value.data();
    size_t      len  = value.size();
    uint64_t    crc  = 0;

    while (len >= sizeof(uint64_t))
    {
        uint64_t word;
        std::memcpy(&word, data, sizeof(word));
        crc = _mm_crc32_u64(crc, word);
        data += sizeof(word);
        len -= sizeof(word);
    }

    if (len >= sizeof(uint32_t))
    {
        uint32_t word;
        std::memcpy(&word, data, sizeof(word));
        crc = _mm_crc32_u32(static_cast<uint32_t>(crc), word);
        data += sizeof(word);
        len -= sizeof(word);
    }

    if (len >= sizeof(uint16_t))
    {
        uint16_t word;
        std::memcpy(&word, data, sizeof(word));
        crc = _mm_crc32_u16(static_cast<uint32_t>(crc), word);
        data += sizeof(word);
        len -= sizeof(word);
    }

    if (len == sizeof(uint8_t))
        crc = _mm_crc32_u8(static_cast<uint32_t>(crc), static_cast<uint8_t>(*data));

    return static_cast<size_t>(crc);
}

inline bool cpu_supports_sse42() noexcept
{
    static const bool supported = __builtin_cpu_supports("sse4.2");
    return supported;
}

#endif

inline size_t crc32_or_fallback(std::string_view value) noexcept
{
#if DNS_PRO_HAS_TARGETED_SSE42
    if (cpu_supports_sse42())
        return crc32_sse42(value);
#endif

    return static_cast<size_t>(XXH3_64bits(value.data(), value.size()));
}

} // namespace HashDetail

struct DomainHash
{
    size_t operator()(const std::string &domain) const noexcept { return HashDetail::crc32_or_fallback(domain); }
};

struct SvCRC32
{
    using is_transparent = void;

    size_t operator()(std::string_view value) const noexcept { return HashDetail::crc32_or_fallback(value); }
};

struct XXH3_64
{
    size_t operator()(std::string_view value) const noexcept { return static_cast<size_t>(XXH3_64bits(value.data(), value.size())); }
};

inline XXH64_hash_t xxH3_64bits(std::string_view value) noexcept
{
    return XXH3_64bits(value.data(), value.size());
}

#undef DNS_PRO_HAS_TARGETED_SSE42
