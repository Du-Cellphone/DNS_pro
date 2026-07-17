#include "FilterContext.h"

#include <memory>
#include <utility>

namespace dns::server
{

FilterSnapshotBuild build_filter_snapshot(std::span<const std::string> rules, FilterGeneration generation, std::stop_token stop_token)
{
    auto blocklist = Filter::DomainBlocklist::build(rules, stop_token);
    if (!blocklist)
        return dns::unexpected(blocklist.error());
    if (stop_token.stop_requested())
        return dns::unexpected(Filter::BlocklistBuildError{Filter::BlocklistBuildErrorCode::Cancelled, 0});
    return std::make_shared<const FilterContext>(generation, std::move(*blocklist));
}

} // namespace dns::server
