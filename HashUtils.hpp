#pragma once

#include <cstddef>
#include <string>
#include <cstddef>
#include <cstdint>
#include <nmmintrin.h>
#include <string_view>
#define XXH_INLINE_ALL
#include "xxhash.h"


struct DomainHash
{
    size_t operator()(const std::string &d) const
    {
        const char *data = d.data();
        size_t      len  = d.size();

        uint64_t crc = 0;

        while (len >= 8)
        {
            crc = _mm_crc32_u64(crc, *reinterpret_cast<const uint64_t *>(data));
            data += 8;
            len -= 8;
        }

        while (len >= 4)
        {
            crc = _mm_crc32_u32(crc, *reinterpret_cast<const uint32_t *>(data));
            data += 4;
            len -= 4;
        }

        while (len >= 2)
        {
            crc = _mm_crc32_u16(crc, *reinterpret_cast<const uint16_t *>(data));
            data += 2;
            len -= 2;
        }

        if (len >= 1)
            crc = _mm_crc32_u8(crc, *reinterpret_cast<const uint8_t *>(data));

        return static_cast<size_t>(crc);
    }
};

struct SvCRC32
{
    size_t operator()(std::string_view sv) const noexcept
    {
        const char *data = sv.data();
        size_t      len  = sv.size();
        uint64_t    crc  = 0;
        while (len >= 8)
        {
            crc = _mm_crc32_u64(crc, *reinterpret_cast<const uint64_t *>(data));
            data += 8;
            len -= 8;
        }
        while (len >= 4)
        {
            crc = _mm_crc32_u32(crc, *reinterpret_cast<const uint32_t *>(data));
            data += 4;
            len -= 4;
        }
        while (len >= 2)
        {
            crc = _mm_crc32_u16(crc, *reinterpret_cast<const uint16_t *>(data));
            data += 2;
            len -= 2;
        }
        if (len)
        {
            crc = _mm_crc32_u8(crc, *reinterpret_cast<const uint8_t *>(data));
        }
        return static_cast<size_t>(crc);
    }
};

struct XXH3_64
{
    size_t operator()(const std::string_view &sv) const noexcept { return static_cast<size_t>(XXH3_64bits(sv.data(), sv.size())); }
};

inline XXH64_hash_t xxH3_64bits(const std::string_view sv)
{
    return XXH3_64bits(sv.data(), sv.size());
}
