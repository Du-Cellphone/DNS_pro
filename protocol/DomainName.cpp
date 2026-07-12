#include "protocol/DomainName.h"

#include <cstdint>
#include <utility>

namespace dns::protocol
{
namespace
{

char ascii_lower(char value) noexcept
{
    const auto byte = static_cast<unsigned char>(value);
    if (byte >= static_cast<unsigned char>('A') && byte <= static_cast<unsigned char>('Z'))
        return static_cast<char>(byte + ('a' - 'A'));
    return value;
}

bool is_ascii_digit(char value) noexcept
{
    const auto byte = static_cast<unsigned char>(value);
    return byte >= static_cast<unsigned char>('0') && byte <= static_cast<unsigned char>('9');
}

std::string label_to_presentation(std::string_view label, bool canonical)
{
    std::string result;
    result.reserve(label.size());

    for (char value : label)
    {
        const auto byte = static_cast<unsigned char>(canonical ? ascii_lower(value) : value);
        if (byte == static_cast<unsigned char>('.') || byte == static_cast<unsigned char>('\\'))
        {
            result.push_back('\\');
            result.push_back(static_cast<char>(byte));
        }
        else if (byte >= 0x21U && byte <= 0x7eU)
        {
            result.push_back(static_cast<char>(byte));
        }
        else
        {
            result.push_back('\\');
            result.push_back(static_cast<char>('0' + byte / 100U));
            result.push_back(static_cast<char>('0' + (byte / 10U) % 10U));
            result.push_back(static_cast<char>('0' + byte % 10U));
        }
    }

    return result;
}

bool labels_equal_canonical(std::string_view lhs, std::string_view rhs) noexcept
{
    if (lhs.size() != rhs.size())
        return false;

    for (size_t index = 0; index < lhs.size(); ++index)
    {
        if (ascii_lower(lhs[index]) != ascii_lower(rhs[index]))
            return false;
    }
    return true;
}

} // namespace

Expected<DomainName, DomainNameError> DomainName::from_text(std::string_view text)
{
    if (text.empty() || text == ".")
        return DomainName{};

    std::vector<std::string> labels;
    std::string              label;

    for (size_t index = 0; index < text.size(); ++index)
    {
        const char value = text[index];
        if (value == '.')
        {
            if (label.empty())
                return dns::unexpected(DomainNameError{DomainNameErrorCode::EmptyLabel, labels.size()});
            labels.push_back(std::move(label));
            label.clear();
            if (index + 1 == text.size())
                return from_labels(std::move(labels));
            continue;
        }

        if (value != '\\')
        {
            label.push_back(value);
            continue;
        }

        if (index + 1 >= text.size())
            return dns::unexpected(DomainNameError{DomainNameErrorCode::InvalidEscape, labels.size()});

        const size_t remaining = text.size() - (index + 1);
        if (remaining >= 3 && is_ascii_digit(text[index + 1]) && is_ascii_digit(text[index + 2]) && is_ascii_digit(text[index + 3]))
        {
            const unsigned int byte = static_cast<unsigned int>(text[index + 1] - '0') * 100U +
                                      static_cast<unsigned int>(text[index + 2] - '0') * 10U +
                                      static_cast<unsigned int>(text[index + 3] - '0');
            if (byte > 255U)
                return dns::unexpected(DomainNameError{DomainNameErrorCode::InvalidEscape, labels.size()});
            label.push_back(static_cast<char>(byte));
            index += 3;
        }
        else
        {
            label.push_back(text[++index]);
        }
    }

    if (label.empty())
    {
        if (labels.empty())
            return dns::unexpected(DomainNameError{DomainNameErrorCode::EmptyLabel, labels.size()});
        return from_labels(std::move(labels));
    }

    labels.push_back(std::move(label));
    return from_labels(std::move(labels));
}

Expected<DomainName, DomainNameError> DomainName::from_labels(std::vector<std::string> labels)
{
    size_t      wire_size = 1;
    std::string canonical_key;

    for (size_t index = 0; index < labels.size(); ++index)
    {
        const std::string &label = labels[index];
        if (label.empty())
            return dns::unexpected(DomainNameError{DomainNameErrorCode::EmptyLabel, index});
        if (label.size() > kMaxLabelSize)
            return dns::unexpected(DomainNameError{DomainNameErrorCode::LabelTooLong, index});
        if (wire_size > kMaxDomainWireSize - (label.size() + 1))
            return dns::unexpected(DomainNameError{DomainNameErrorCode::NameTooLong, index});

        wire_size += label.size() + 1;
    }

    canonical_key.reserve(wire_size);
    for (const std::string &label : labels)
    {
        canonical_key.push_back(static_cast<char>(label.size()));
        for (char value : label)
            canonical_key.push_back(ascii_lower(value));
    }
    canonical_key.push_back('\0');

    return DomainName{std::move(labels), wire_size, std::move(canonical_key)};
}

std::string DomainName::to_string() const
{
    if (is_root())
        return ".";

    std::string result;
    for (size_t index = 0; index < labels_.size(); ++index)
    {
        if (index != 0)
            result.push_back('.');
        result += label_to_presentation(labels_[index], false);
    }
    return result;
}

std::string DomainName::to_canonical_string() const
{
    if (is_root())
        return ".";

    std::string result;
    for (size_t index = 0; index < labels_.size(); ++index)
    {
        if (index != 0)
            result.push_back('.');
        result += label_to_presentation(labels_[index], true);
    }
    return result;
}

bool DomainName::is_subdomain_of(const DomainName &parent) const noexcept
{
    if (parent.labels_.size() > labels_.size())
        return false;

    const size_t offset = labels_.size() - parent.labels_.size();
    for (size_t index = 0; index < parent.labels_.size(); ++index)
    {
        if (!labels_equal_canonical(labels_[offset + index], parent.labels_[index]))
            return false;
    }
    return true;
}

} // namespace dns::protocol
