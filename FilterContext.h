#pragma once

#include "DomainBlocklist.h"
#include "common/Expected.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <span>
#include <stop_token>
#include <string>
#include <utility>

namespace dns::server
{

using FilterGeneration = uint64_t;

inline constexpr FilterGeneration kInitialFilterGeneration = 1;

struct FilterContext final
{
    FilterContext(FilterGeneration value_generation, Filter::DomainBlocklist value)
        : generation(value_generation)
        , blocklist(std::move(value))
    {
    }

    FilterGeneration        generation{kInitialFilterGeneration};
    Filter::DomainBlocklist blocklist;
};

using FilterSnapshot      = std::shared_ptr<const FilterContext>;
using FilterSnapshotSlot  = std::atomic<FilterSnapshot>;
using FilterSnapshotBuild = std::expected<FilterSnapshot, Filter::BlocklistBuildError>;

FilterSnapshotBuild build_filter_snapshot(std::span<const std::string> rules, FilterGeneration generation, std::stop_token stop_token = {});

} // namespace dns::server
