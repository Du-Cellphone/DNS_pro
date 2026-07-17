#include "FilterContext.h"

#include <memory>
#include <utility>

namespace dns::server
{

FilterSnapshotBuild build_filter_snapshot(std::span<const std::string> rules)
{
    auto blocklist = Filter::DomainBlocklist::build(rules);
    if (!blocklist)
        return dns::unexpected(blocklist.error());
    return std::make_shared<const FilterContext>(std::move(*blocklist));
}

} // namespace dns::server
