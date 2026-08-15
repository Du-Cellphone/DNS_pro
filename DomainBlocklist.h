#pragma once

#include "CuckooFilter.h"
#include "RadixTree.h"
#include "common/Expected.h"
#include "protocol/DomainName.h"

#include <cstddef>
#include <span>
#include <stop_token>
#include <string>

namespace Filter
{

enum class BlocklistBuildErrorCode
{
    InvalidDomain,
    RootRuleNotAllowed,
    WildcardNotSupported,
    CapacityOverflow,
    Cancelled,
};

struct BlocklistBuildError
{
    BlocklistBuildErrorCode code;
    size_t                  rule_index{0};

    bool operator==(const BlocklistBuildError &) const = default;
};

class DomainBlocklist final
{
public:
    DomainBlocklist();
    DomainBlocklist(DomainBlocklist &&) noexcept            = default;
    DomainBlocklist &operator=(DomainBlocklist &&) noexcept = default;
    DomainBlocklist(const DomainBlocklist &)                = delete;
    DomainBlocklist &operator=(const DomainBlocklist &)     = delete;

    static std::expected<DomainBlocklist, BlocklistBuildError> build(std::span<const std::string> rules,
                                                                     std::stop_token                stop_token = {});

    [[nodiscard]] bool   matches(const dns::protocol::DomainName &query) const noexcept;
    [[nodiscard]] bool   matches(std::string_view query) const;
    [[nodiscard]] size_t rule_count() const noexcept { return rule_count_; }

private:
    explicit DomainBlocklist(size_t bucket_count);

    CuckooFilter prefilter_;
    RadixTree    tree_;
    size_t       rule_count_{0};
};

} // namespace Filter
