#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace dns::protocol::detail
{

class WireReader
{
public:
    explicit WireReader(std::span<const std::byte> bytes, size_t offset = 0) noexcept
        : bytes_(bytes)
        , offset_(offset)
    {
    }

    [[nodiscard]] size_t offset() const noexcept { return offset_; }
    [[nodiscard]] size_t remaining() const noexcept { return offset_ <= bytes_.size() ? bytes_.size() - offset_ : 0; }

    bool read_u8(uint8_t &value) noexcept
    {
        if (remaining() < 1)
            return false;
        value = std::to_integer<uint8_t>(bytes_[offset_++]);
        return true;
    }

    bool read_u16(uint16_t &value) noexcept
    {
        if (remaining() < 2)
            return false;
        value = static_cast<uint16_t>((static_cast<uint16_t>(std::to_integer<uint8_t>(bytes_[offset_])) << 8U) |
                                      static_cast<uint16_t>(std::to_integer<uint8_t>(bytes_[offset_ + 1])));
        offset_ += 2;
        return true;
    }

    bool read_u32(uint32_t &value) noexcept
    {
        if (remaining() < 4)
            return false;
        value = (static_cast<uint32_t>(std::to_integer<uint8_t>(bytes_[offset_])) << 24U) |
                (static_cast<uint32_t>(std::to_integer<uint8_t>(bytes_[offset_ + 1])) << 16U) |
                (static_cast<uint32_t>(std::to_integer<uint8_t>(bytes_[offset_ + 2])) << 8U) |
                static_cast<uint32_t>(std::to_integer<uint8_t>(bytes_[offset_ + 3]));
        offset_ += 4;
        return true;
    }

    bool read_bytes(size_t count, std::vector<std::byte> &output)
    {
        if (remaining() < count)
            return false;
        output.assign(bytes_.begin() + static_cast<std::ptrdiff_t>(offset_),
                      bytes_.begin() + static_cast<std::ptrdiff_t>(offset_ + count));
        offset_ += count;
        return true;
    }

    bool skip(size_t count) noexcept
    {
        if (remaining() < count)
            return false;
        offset_ += count;
        return true;
    }

private:
    std::span<const std::byte> bytes_;
    size_t                     offset_{0};
};

class WireWriter
{
public:
    explicit WireWriter(size_t maximum_size)
        : maximum_size_(maximum_size)
    {
        bytes_.reserve(maximum_size < 512 ? maximum_size : 512);
    }

    [[nodiscard]] size_t size() const noexcept { return bytes_.size(); }

    bool write_u8(uint8_t value)
    {
        if (!can_append(1))
            return false;
        bytes_.push_back(static_cast<std::byte>(value));
        return true;
    }

    bool write_u16(uint16_t value)
    {
        if (!can_append(2))
            return false;
        bytes_.push_back(static_cast<std::byte>((value >> 8U) & 0xffU));
        bytes_.push_back(static_cast<std::byte>(value & 0xffU));
        return true;
    }

    bool write_u32(uint32_t value)
    {
        if (!can_append(4))
            return false;
        bytes_.push_back(static_cast<std::byte>((value >> 24U) & 0xffU));
        bytes_.push_back(static_cast<std::byte>((value >> 16U) & 0xffU));
        bytes_.push_back(static_cast<std::byte>((value >> 8U) & 0xffU));
        bytes_.push_back(static_cast<std::byte>(value & 0xffU));
        return true;
    }

    bool write_bytes(std::span<const std::byte> bytes)
    {
        if (!can_append(bytes.size()))
            return false;
        bytes_.insert(bytes_.end(), bytes.begin(), bytes.end());
        return true;
    }

    std::vector<std::byte> take() && { return std::move(bytes_); }

private:
    bool can_append(size_t count) const noexcept
    {
        return bytes_.size() <= maximum_size_ && count <= maximum_size_ - bytes_.size();
    }

    size_t                 maximum_size_;
    std::vector<std::byte> bytes_;
};

} // namespace dns::protocol::detail
