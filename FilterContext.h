#pragma once

#include "DomainBlocklist.h"
#include "common/Expected.h"

#include <atomic>
#include <memory>
#include <span>
#include <string>
#include <utility>

namespace dns::server
{

struct FilterContext final
{
    explicit FilterContext(Filter::DomainBlocklist value)
        : blocklist(std::move(value))
    {
    }

    Filter::DomainBlocklist blocklist;
};

using FilterSnapshot      = std::shared_ptr<const FilterContext>;
using FilterSnapshotSlot  = std::atomic<FilterSnapshot>;
using FilterSnapshotBuild = Expected<FilterSnapshot, Filter::BlocklistBuildError>;

FilterSnapshotBuild build_filter_snapshot(std::span<const std::string> rules);

} // namespace dns::server
