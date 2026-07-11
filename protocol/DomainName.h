#pragma once

#include <cstddef>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace dns::protocol
{

inline constexpr size_t kMaxLabelSize      = 63;
inline constexpr size_t kMaxDomainWireSize = 255;

enum class DomainNameErrorCode
{
    EmptyLabel,
    InvalidEscape,
    LabelTooLong,
    NameTooLong,
};

struct DomainNameError
{
    DomainNameErrorCode code;
    size_t              label_index{0};

    bool operator==(const DomainNameError &) const = default;
};

class DomainName
{
public:
    DomainName() = default;

    static std::expected<DomainName, DomainNameError> from_text(std::string_view text);
    static std::expected<DomainName, DomainNameError> from_labels(std::vector<std::string> labels);

    [[nodiscard]] bool                         is_root() const noexcept { return labels_.empty(); }
    [[nodiscard]] size_t                       wire_size() const noexcept { return wire_size_; }
    [[nodiscard]] std::span<const std::string> labels() const noexcept { return labels_; }
    [[nodiscard]] std::string_view             canonical_key() const noexcept { return canonical_key_; }

    [[nodiscard]] std::string to_string() const;
    [[nodiscard]] std::string to_canonical_string() const;
    [[nodiscard]] bool        is_subdomain_of(const DomainName &parent) const noexcept;

    bool operator==(const DomainName &other) const noexcept { return canonical_key_ == other.canonical_key_; }

private:
    DomainName(std::vector<std::string> labels, size_t wire_size, std::string canonical_key)
        : labels_(std::move(labels))
        , wire_size_(wire_size)
        , canonical_key_(std::move(canonical_key))
    {
    }

    std::vector<std::string> labels_;
    size_t                   wire_size_{1};
    std::string              canonical_key_{1, '\0'};
};

} // namespace dns::protocol
