#include "DomainBlocklist.h"

#include "HashUtils.hpp"

#include <limits>
#include <unordered_set>
#include <utility>
#include <vector>

namespace Filter
{
namespace
{

bool contains_unsupported_wildcard(const dns::protocol::DomainName &name) noexcept
{
    for (const std::string &label : name.labels())
    {
        if (label.find_first_of("*?") != std::string::npos)
            return true;
    }
    return false;
}

size_t initial_bucket_count(size_t item_count) noexcept
{
    return item_count < 4 ? 4 : item_count / 3 + 1;
}

} // namespace

DomainBlocklist::DomainBlocklist()
    : prefilter_(4)
{
}

DomainBlocklist::DomainBlocklist(size_t bucket_count)
    : prefilter_(bucket_count)
{
}

dns::Expected<DomainBlocklist, BlocklistBuildError> DomainBlocklist::build(std::span<const std::string> rules, std::stop_token stop_token)
{
    if (stop_token.stop_requested())
        return dns::unexpected(BlocklistBuildError{BlocklistBuildErrorCode::Cancelled, 0});

    std::vector<dns::protocol::DomainName> canonical_rules;
    canonical_rules.reserve(rules.size());
    std::unordered_set<std::string, XXH3_64> unique_rules;
    unique_rules.reserve(rules.size());

    for (size_t index = 0; index < rules.size(); ++index)
    {
        if (stop_token.stop_requested())
            return dns::unexpected(BlocklistBuildError{BlocklistBuildErrorCode::Cancelled, index});

        auto name = dns::protocol::DomainName::from_text(rules[index]);
        if (!name)
            return dns::unexpected(BlocklistBuildError{BlocklistBuildErrorCode::InvalidDomain, index});
        if (name->is_root())
            return dns::unexpected(BlocklistBuildError{BlocklistBuildErrorCode::RootRuleNotAllowed, index});
        if (contains_unsupported_wildcard(*name))
            return dns::unexpected(BlocklistBuildError{BlocklistBuildErrorCode::WildcardNotSupported, index});

        std::string key{name->canonical_key()};
        if (unique_rules.insert(key).second)
            canonical_rules.push_back(std::move(*name));
    }

    size_t bucket_count = initial_bucket_count(canonical_rules.size());
    while (true)
    {
        if (stop_token.stop_requested())
            return dns::unexpected(BlocklistBuildError{BlocklistBuildErrorCode::Cancelled, 0});

        DomainBlocklist candidate{bucket_count};
        bool            inserted_all = true;
        for (size_t index = 0; index < canonical_rules.size(); ++index)
        {
            if (stop_token.stop_requested())
                return dns::unexpected(BlocklistBuildError{BlocklistBuildErrorCode::Cancelled, index});
            const auto &name = canonical_rules[index];
            if (!candidate.prefilter_.insert(name.canonical_key()))
            {
                inserted_all = false;
                break;
            }
        }

        if (inserted_all)
        {
            for (size_t index = 0; index < canonical_rules.size(); ++index)
            {
                if (stop_token.stop_requested())
                    return dns::unexpected(BlocklistBuildError{BlocklistBuildErrorCode::Cancelled, index});
                candidate.tree_.insert(canonical_rules[index]);
            }
            candidate.rule_count_ = canonical_rules.size();
            return candidate;
        }

        if (bucket_count > std::numeric_limits<size_t>::max() / 2)
            return dns::unexpected(BlocklistBuildError{BlocklistBuildErrorCode::CapacityOverflow, 0});
        bucket_count *= 2;
    }
}

bool DomainBlocklist::matches(const dns::protocol::DomainName &query) const noexcept
{
    bool possibly_matches = false;
    for (size_t first_label = 0; first_label < query.label_count(); ++first_label)
    {
        if (prefilter_.contains(query.canonical_suffix_key(first_label)))
        {
            possibly_matches = true;
            break;
        }
    }
    return possibly_matches && tree_.search(query);
}

bool DomainBlocklist::matches(std::string_view query) const
{
    auto normalized = dns::protocol::DomainName::from_text(query);
    return normalized && matches(*normalized);
}

} // namespace Filter
