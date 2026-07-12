#include "../CuckooFilter.h"
#include "../RadixTree.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <memory>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace
{
using Clock = std::chrono::steady_clock;

constexpr size_t kDefaultDomainCount = 200'000;
constexpr size_t kDefaultLookupCount = 1'000'000;
constexpr size_t kDefaultHitPercent  = 10;

volatile std::uint64_t benchmark_sink = 0;

struct Dataset
{
    std::vector<std::string> domains;
    std::vector<std::string> queries;
    size_t                   expected_hits{0};
};

struct BuildStats
{
    std::unique_ptr<RadixTree> tree;
    double                     build_ms{0.0};
};

struct FilterBuildStats
{
    std::unique_ptr<Filter::CuckooFilter> filter;
    double                                build_ms{0.0};
};

struct LookupStats
{
    double ms{0.0};
    size_t hits{0};
};

struct FilterLookupStats
{
    double ms{0.0};
    size_t positives{0};
};

struct PipelineLookupStats
{
    double ms{0.0};
    size_t hits{0};
    size_t tree_checks{0};
};

template <typename Func>
double measure_ms(Func &&func)
{
    const auto start = Clock::now();
    func();
    const auto end = Clock::now();
    return std::chrono::duration<double, std::milli>(end - start).count();
}

size_t parse_or_default(char *arg, const size_t fallback)
{
    try
    {
        return static_cast<size_t>(std::stoull(arg));
    }
    catch (const std::exception &)
    {
        return fallback;
    }
}

std::string make_registered_domain(const size_t id, std::mt19937_64 &rng)
{
    static constexpr std::array<std::string_view, 16> kTlds = {
        "com", "net", "org", "io", "co", "cn", "de", "uk", "jp", "fr", "dev", "app", "cloud", "ai", "shop", "xyz"};
    static constexpr std::array<std::string_view, 16> kBrands = {"nova",  "atlas", "zen",  "pixel", "orbit", "lumen", "aero",  "terra",
                                                                  "swift", "summit", "wave", "cobalt", "ember", "merit", "nexus", "harbor"};
    static constexpr std::array<std::string_view, 12> kVerticals = {
        "tech", "media", "data", "pay", "cloud", "news", "cdn", "video", "mail", "docs", "edge", "market"};
    static constexpr std::array<std::string_view, 10> kPrefixes = {"www", "api", "cdn", "img", "mail", "m", "static", "edge", "auth", "ns1"};
    static constexpr std::array<std::string_view, 8> kRegions = {"us", "eu", "ap", "latam", "mea", "na", "sa", "global"};

    const auto next_index = [&rng](const size_t size) { return static_cast<size_t>(rng() % size); };

    const std::string second_level = std::string(kBrands[next_index(kBrands.size())]) + "-" +
                                     std::string(kVerticals[next_index(kVerticals.size())]) + std::to_string(id);
    const std::string tld = std::string(kTlds[next_index(kTlds.size())]);
    const size_t      pattern = next_index(100);

    if (pattern < 55)
        return second_level + "." + tld;
    if (pattern < 85)
        return std::string(kPrefixes[next_index(kPrefixes.size())]) + "." + second_level + "." + tld;

    return std::string(kRegions[next_index(kRegions.size())]) + "." + std::string(kPrefixes[next_index(kPrefixes.size())]) + "." + second_level + "." + tld;
}

std::string make_absent_domain(const size_t id, std::mt19937_64 &rng)
{
    static constexpr std::array<std::string_view, 10> kTlds = {"net", "org", "io", "co", "app", "dev", "cloud", "site", "online", "tech"};
    static constexpr std::array<std::string_view, 8>  kPrefixes = {"www", "api", "cdn", "img", "m", "static", "edge", "mail"};
    static constexpr std::array<std::string_view, 6>  kRegions = {"us", "eu", "ap", "global", "latam", "mea"};

    const auto next_index = [&rng](const size_t size) { return static_cast<size_t>(rng() % size); };
    const size_t pattern = next_index(100);
    const std::string tld = std::string(kTlds[next_index(kTlds.size())]);

    if (pattern < 70)
        return "lookup-miss-" + std::to_string(id) + "." + tld;

    return std::string(kRegions[next_index(kRegions.size())]) + "." + std::string(kPrefixes[next_index(kPrefixes.size())]) + ".shadow-miss-" + std::to_string(id) + "." + tld;
}

Dataset make_dataset(const size_t domain_count, const size_t lookup_count, const size_t hit_percent)
{
    if (domain_count < 100'000)
        throw std::invalid_argument("domain_count must be at least 100000");
    if (lookup_count == 0)
        throw std::invalid_argument("lookup_count must be greater than zero");
    if (hit_percent > 100)
        throw std::invalid_argument("hit_percent must be in [0, 100]");

    Dataset         dataset;
    std::mt19937_64 rng(42);

    dataset.domains.reserve(domain_count);
    for (size_t id = 0; id < domain_count; ++id)
        dataset.domains.push_back(make_registered_domain(id, rng));

    const size_t hit_count = (lookup_count * hit_percent) / 100;
    std::uniform_int_distribution<size_t> pick_domain(0, dataset.domains.size() - 1);

    dataset.queries.reserve(lookup_count);
    for (size_t idx = 0; idx < hit_count; ++idx)
        dataset.queries.push_back(dataset.domains[pick_domain(rng)]);
    for (size_t idx = hit_count; idx < lookup_count; ++idx)
        dataset.queries.push_back(make_absent_domain(domain_count + idx, rng));

    std::shuffle(dataset.domains.begin(), dataset.domains.end(), rng);
    std::shuffle(dataset.queries.begin(), dataset.queries.end(), rng);
    dataset.expected_hits = hit_count;
    return dataset;
}

size_t estimate_filter_bucket_count(const size_t item_count)
{
    const size_t numerator = item_count * 100ULL;
    const size_t denominator = Filter::FPS_PER_BUCKET * 90ULL;
    const size_t buckets = numerator / denominator + 1ULL;
    return std::max<size_t>(4ULL, buckets);
}

BuildStats build_tree(const std::vector<std::string> &domains)
{
    BuildStats stats;
    stats.build_ms = measure_ms([&]() {
        stats.tree = std::make_unique<RadixTree>();
        for (const std::string &domain : domains)
            stats.tree->insert(domain);
    });
    return stats;
}

FilterBuildStats build_filter(const std::vector<std::string> &domains)
{
    FilterBuildStats stats;
    stats.build_ms = measure_ms([&]() {
        stats.filter = std::make_unique<Filter::CuckooFilter>(estimate_filter_bucket_count(domains.size()));
        for (const std::string &domain : domains)
        {
            auto normalized = dns::protocol::DomainName::from_text(domain);
            if (!normalized || !stats.filter->insert(normalized->canonical_key()))
                throw std::runtime_error("failed to insert domain into CuckooFilter");
        }
    });
    return stats;
}

LookupStats run_tree_lookup(const RadixTree &tree, const std::vector<std::string> &queries)
{
    LookupStats stats;
    stats.ms = measure_ms([&]() {
        for (const std::string &query : queries)
        {
            const bool found = tree.search(query);
            stats.hits += found ? 1ULL : 0ULL;
            benchmark_sink += found ? 1ULL : 0ULL;
        }
    });
    return stats;
}

FilterLookupStats run_filter_lookup(const Filter::CuckooFilter &filter, const std::vector<std::string> &queries)
{
    FilterLookupStats stats;
    stats.ms = measure_ms([&]() {
        for (const std::string &query : queries)
        {
            auto normalized = dns::protocol::DomainName::from_text(query);
            const bool positive = normalized && filter.contains(normalized->canonical_key());
            stats.positives += positive ? 1ULL : 0ULL;
            benchmark_sink += positive ? 1ULL : 0ULL;
        }
    });
    return stats;
}

PipelineLookupStats run_pipeline_lookup(const Filter::CuckooFilter &filter, const RadixTree &tree, const std::vector<std::string> &queries)
{
    PipelineLookupStats stats;
    stats.ms = measure_ms([&]() {
        for (const std::string &query : queries)
        {
            auto normalized = dns::protocol::DomainName::from_text(query);
            if (!normalized)
                continue;

            bool possibly_matches = false;
            for (size_t first_label = 0; first_label < normalized->label_count(); ++first_label)
            {
                if (filter.contains(normalized->canonical_suffix_key(first_label)))
                {
                    possibly_matches = true;
                    break;
                }
            }
            if (!possibly_matches)
                continue;

            ++stats.tree_checks;
            const bool found = tree.search(*normalized);
            stats.hits += found ? 1ULL : 0ULL;
            benchmark_sink += found ? 1ULL : 0ULL;
        }
    });
    return stats;
}

void print_summary(const Dataset &dataset,
                   const BuildStats &tree_only_build,
                   const LookupStats &tree_only_lookup,
                   const FilterBuildStats &filter_build,
                   const FilterLookupStats &filter_lookup,
                   const BuildStats &filtered_tree_build,
                   const PipelineLookupStats &pipeline_lookup)
{
    const double tree_total_ms = tree_only_build.build_ms + tree_only_lookup.ms;
    const double filter_total_ms = filter_build.build_ms + filter_lookup.ms;
    const double pipeline_build_ms = filter_build.build_ms + filtered_tree_build.build_ms;
    const double pipeline_total_ms = pipeline_build_ms + pipeline_lookup.ms;
    const size_t false_positives = filter_lookup.positives > dataset.expected_hits ? filter_lookup.positives - dataset.expected_hits : 0ULL;
    const size_t skipped_tree_checks = dataset.queries.size() - pipeline_lookup.tree_checks;

    std::cout << std::fixed << std::setprecision(3);
    std::cout << "Dataset\n";
    std::cout << "  inserted domains : " << dataset.domains.size() << '\n';
    std::cout << "  lookup queries   : " << dataset.queries.size() << '\n';
    std::cout << "  expected hits    : " << dataset.expected_hits << '\n';
    std::cout << "  expected misses  : " << (dataset.queries.size() - dataset.expected_hits) << "\n\n";

    std::cout << "RadixTree only\n";
    std::cout << "  build ms         : " << tree_only_build.build_ms << '\n';
    std::cout << "  lookup ms        : " << tree_only_lookup.ms << '\n';
    std::cout << "  total ms         : " << tree_total_ms << '\n';
    std::cout << "  hits             : " << tree_only_lookup.hits << "\n\n";

    std::cout << "CuckooFilter only\n";
    std::cout << "  build ms         : " << filter_build.build_ms << '\n';
    std::cout << "  lookup ms        : " << filter_lookup.ms << '\n';
    std::cout << "  total ms         : " << filter_total_ms << '\n';
    std::cout << "  positives        : " << filter_lookup.positives << '\n';
    std::cout << "  false positives  : " << false_positives << '\n';
    std::cout << "  fp rate          : "
              << (dataset.queries.size() == dataset.expected_hits ? 0.0
                                                                  : static_cast<double>(false_positives) /
                                                                        static_cast<double>(dataset.queries.size() - dataset.expected_hits) * 100.0)
              << "%\n\n";

    std::cout << "CuckooFilter + RadixTree\n";
    std::cout << "  cuckoo build ms  : " << filter_build.build_ms << '\n';
    std::cout << "  tree build ms    : " << filtered_tree_build.build_ms << '\n';
    std::cout << "  build total ms   : " << pipeline_build_ms << '\n';
    std::cout << "  lookup ms        : " << pipeline_lookup.ms << '\n';
    std::cout << "  total ms         : " << pipeline_total_ms << '\n';
    std::cout << "  final hits       : " << pipeline_lookup.hits << '\n';
    std::cout << "  tree checks      : " << pipeline_lookup.tree_checks << '\n';
    std::cout << "  checks skipped   : " << skipped_tree_checks << '\n';
    std::cout << "  lookup speedup   : " << (pipeline_lookup.ms == 0.0 ? 0.0 : tree_only_lookup.ms / pipeline_lookup.ms) << "x\n";
    std::cout << "  total speedup    : " << (pipeline_total_ms == 0.0 ? 0.0 : tree_total_ms / pipeline_total_ms) << "x\n";
}

} // namespace

int main(int argc, char **argv)
{
    const size_t domain_count = argc > 1 ? parse_or_default(argv[1], kDefaultDomainCount) : kDefaultDomainCount;
    const size_t lookup_count = argc > 2 ? parse_or_default(argv[2], kDefaultLookupCount) : kDefaultLookupCount;
    const size_t hit_percent = argc > 3 ? parse_or_default(argv[3], kDefaultHitPercent) : kDefaultHitPercent;

    try
    {
        const Dataset dataset = make_dataset(domain_count, lookup_count, hit_percent);

        const BuildStats tree_only_build = build_tree(dataset.domains);
        const LookupStats tree_only_lookup = run_tree_lookup(*tree_only_build.tree, dataset.queries);

        const FilterBuildStats filter_build = build_filter(dataset.domains);
        const FilterLookupStats filter_lookup = run_filter_lookup(*filter_build.filter, dataset.queries);

        const BuildStats filtered_tree_build = build_tree(dataset.domains);
        const PipelineLookupStats pipeline_lookup = run_pipeline_lookup(*filter_build.filter, *filtered_tree_build.tree, dataset.queries);

        if (tree_only_lookup.hits != dataset.expected_hits)
            throw std::runtime_error("RadixTree benchmark returned an unexpected hit count");
        if (pipeline_lookup.hits != dataset.expected_hits)
            throw std::runtime_error("Pipeline benchmark returned an unexpected hit count");

        print_summary(dataset, tree_only_build, tree_only_lookup, filter_build, filter_lookup, filtered_tree_build, pipeline_lookup);
        std::cout << "\nbenchmark sink    : " << benchmark_sink << '\n';
    }
    catch (const std::exception &ex)
    {
        std::cerr << "benchmark failed: " << ex.what() << '\n';
        return 1;
    }

    return 0;
}
