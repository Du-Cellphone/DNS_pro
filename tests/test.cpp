// benchmark_trie_v2.cpp
// cl /O2 /std:c++20 /arch:AVX2 benchmark_trie_v2.cpp
#pragma once
#include <algorithm>
#include <array>
#include <chrono>
#include <deque>
#include <memory>
#include <nmmintrin.h>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include "../HashUtils.hpp"

// ── 公共工具 ────────────────────────────────────────────────────────────────
static std::vector<std::string_view> split_reverse(std::string_view domain)
{
    std::vector<std::string_view> labels;
    labels.reserve(5);
    size_t end = domain.size();
    while (end > 0)
    {
        size_t s = domain.find_last_of('.', end - 1);
        if (s == std::string_view::npos)
        {
            labels.push_back(domain.substr(0, end));
            break;
        }
        labels.push_back(domain.substr(s + 1, end - s - 1));
        end = s;
    }
    return labels;
}

// ── 策略A: unordered_map + 默认 hash（当前实现）─────────────────────────────
struct NodeA
{
    std::unordered_map<std::string_view, std::unique_ptr<NodeA>, XXH3_64> children;
    bool                                                                  is_end = false;
};
struct TrieA
{
    std::unique_ptr<NodeA>  root = std::make_unique<NodeA>();
    std::deque<std::string> storage;
    void                    insert(const std::string &d)
    {
        storage.push_back(d);
        auto   labels = split_reverse(storage.back());
        NodeA *cur    = root.get();
        for (auto lbl : labels)
        {
            auto &c = cur->children[lbl];
            if (!c)
                c = std::make_unique<NodeA>();
            cur = c.get();
        }
        cur->is_end = true;
    }
    bool search(std::string_view d) const
    {
        auto         labels = split_reverse(d);
        const NodeA *cur    = root.get();
        for (auto lbl : labels)
        {
            auto it = cur->children.find(lbl);
            if (it == cur->children.end())
                return false;
            cur = it->second.get();
            if (cur->is_end)
                return true;
        }
        return cur->is_end;
    }
};

// ── 策略B: unordered_map + CRC32 hash（你说可以用的优化）───────────────────
struct NodeB
{
    std::unordered_map<std::string_view, std::unique_ptr<NodeB>, SvCRC32> children;
    bool                                                                  is_end = false;
};
struct TrieB
{
    std::unique_ptr<NodeB>  root = std::make_unique<NodeB>();
    std::deque<std::string> storage;
    void                    insert(const std::string &d)
    {
        storage.push_back(d);
        auto   labels = split_reverse(storage.back());
        NodeB *cur    = root.get();
        for (auto lbl : labels)
        {
            auto &c = cur->children[lbl];
            if (!c)
                c = std::make_unique<NodeB>();
            cur = c.get();
        }
        cur->is_end = true;
    }
    bool search(std::string_view d) const
    {
        auto         labels = split_reverse(d);
        const NodeB *cur    = root.get();
        for (auto lbl : labels)
        {
            auto it = cur->children.find(lbl);
            if (it == cur->children.end())
                return false;
            cur = it->second.get();
            if (cur->is_end)
                return true;
        }
        return cur->is_end;
    }
};


// ── 策略C: sorted vector + binary search（先全插后排序，避免 O(n²) 建树）──
struct NodeC
{
    std::vector<std::pair<std::string_view, std::unique_ptr<NodeC>>> children;
    bool                                                             is_end = false;
    bool                                                             sorted = false;

    void finalize()
    {
        std::sort(children.begin(), children.end(), [](const auto &a, const auto &b) { return a.first < b.first; });
        sorted = true;
        for (auto &[k, v] : children)
            v->finalize();
    }

    NodeC *find_child(std::string_view key) const
    {
        auto it = std::lower_bound(children.begin(), children.end(), key, [](const auto &p, std::string_view k) { return p.first < k; });
        if (it != children.end() && it->first == key)
            return it->second.get();
        return nullptr;
    }

    NodeC *get_or_create_unsorted(std::string_view key)
    {
        for (auto &[k, v] : children)
            if (k == key)
                return v.get();
        children.emplace_back(key, std::make_unique<NodeC>());
        return children.back().second.get();
    }
};
struct TrieC
{
    std::unique_ptr<NodeC>  root = std::make_unique<NodeC>();
    std::deque<std::string> storage;
    void                    insert(const std::string &d)
    {
        storage.push_back(d);
        auto   labels = split_reverse(storage.back());
        NodeC *cur    = root.get();
        for (auto lbl : labels)
            cur = cur->get_or_create_unsorted(lbl);
        cur->is_end = true;
    }
    void build() { root->finalize(); } // 全部插入完成后调用一次
    bool search(std::string_view d) const
    {
        auto         labels = split_reverse(d);
        const NodeC *cur    = root.get();
        for (auto lbl : labels)
        {
            cur = cur->find_child(lbl);
            if (!cur)
                return false;
            if (cur->is_end)
                return true;
        }
        return cur->is_end;
    }
};

// ── 策略D: vector + linear search（小节点最优）──────────────────────────────
struct NodeD
{
    std::vector<std::pair<std::string_view, std::unique_ptr<NodeD>>> children;
    bool                                                             is_end = false;

    NodeD *find_child(std::string_view key) const
    {
        for (auto &[k, v] : children)
            if (k == key)
                return v.get();
        return nullptr;
    }
    NodeD *get_or_create(std::string_view key)
    {
        for (auto &[k, v] : children)
            if (k == key)
                return v.get();
        children.emplace_back(key, std::make_unique<NodeD>());
        return children.back().second.get();
    }
};
struct TrieD
{
    std::unique_ptr<NodeD>  root = std::make_unique<NodeD>();
    std::deque<std::string> storage;
    void                    insert(const std::string &d)
    {
        storage.push_back(d);
        auto   labels = split_reverse(storage.back());
        NodeD *cur    = root.get();
        for (auto lbl : labels)
            cur = cur->get_or_create(lbl);
        cur->is_end = true;
    }
    bool search(std::string_view d) const
    {
        auto         labels = split_reverse(d);
        const NodeD *cur    = root.get();
        for (auto lbl : labels)
        {
            cur = cur->find_child(lbl);
            if (!cur)
                return false;
            if (cur->is_end)
                return true;
        }
        return cur->is_end;
    }
};

// ── 写实数据生成：各 TLD 下独立域名，无单节点超大分支 ──────────────────────
static std::vector<std::string> make_realistic_domains(int n)
{
    // 20 个常见 TLD
    std::array<const char *, 20> tlds = {"com", "net", "org", "io", "co", "ru", "cn", "de", "uk", "fr",
                                         "jp",  "br",  "au",  "in", "ca", "mx", "es", "it", "nl", "se"};
    std::vector<std::string>     v;
    v.reserve(n);

    // 60%: 独立二级域 → domain_N.tld  （com 下最多 3000 个，分散在 20 个 TLD 上）
    int flat = n * 6 / 10;
    for (int i = 0; i < flat; ++i)
        v.push_back("domain" + std::to_string(i) + "." + tlds[i % tlds.size()]);

    // 25%: 一级子域 → sub_M.parent_N.tld  (每个父域最多 5 条子域)
    int one_sub = n * 25 / 100;
    for (int i = 0; i < one_sub; ++i)
        v.push_back("sub" + std::to_string(i % 5) + ".domain" + std::to_string(i / 5) + "." + tlds[(i / 5) % tlds.size()]);

    // 15%: 二级子域 → svc_K.sub_M.parent_N.tld  (3 层深度)
    int rem = n - static_cast<int>(v.size());
    for (int i = 0; i < rem; ++i)
        v.push_back("svc" + std::to_string(i % 3) + ".sub" + std::to_string(i % 5) + ".domain" + std::to_string(i / 15) + "." +
                    tlds[(i / 15) % tlds.size()]);
    return v;
}

// ── 基准框架：分离建树与查询 ─────────────────────────────────────────────────
template <typename BuildFn, typename SearchFn>
void bench(const char *name, BuildFn &&build_fn, SearchFn &&search_fn, const std::vector<std::string> &queries)
{
    build_fn(); // 建树，不计入查询时间

    // warm-up
    volatile int dummy = 0;
    for (int i = 0; i < 10000; ++i)
        dummy += search_fn(queries[i % queries.size()]) ? 1 : 0;

    constexpr int ITERS = 5'000'000;
    auto          t0    = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < ITERS; ++i)
        dummy += search_fn(queries[i % queries.size()]) ? 1 : 0;
    auto t1 = std::chrono::high_resolution_clock::now();

    double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    printf("%-40s %8.1f ms  %4lld M ops/s  [dummy=%d]\n", name, ms, (long long)(ITERS / (ms / 1000.0) / 1e6), dummy);
}

int main()
{
    constexpr int N       = 100'000;
    auto          domains = make_realistic_domains(N);

    // 查询集：50% 命中，50% miss
    std::vector<std::string> queries;
    queries.reserve(10000);
    for (int i = 0; i < 5000; ++i)
        queries.push_back(domains[i]);
    for (int i = 0; i < 5000; ++i)
        queries.push_back("notexist" + std::to_string(i) + ".xyz");

    printf("Domains: %d  |  Query patterns: %zu  |  Querying only (build excluded)\n\n", N, queries.size());

    {
        TrieA t;
        for (auto &d : domains)
            t.insert(d);
        bench("unordered_map + default hash (A)", [] {}, [&](std::string_view q) { return t.search(q); }, queries);
    }
    {
        TrieB t;
        for (auto &d : domains)
            t.insert(d);
        bench("unordered_map + CRC32 hash  (B)", [] {}, [&](std::string_view q) { return t.search(q); }, queries);
    }
    {
        TrieC t;
        for (auto &d : domains)
            t.insert(d);
        t.build();
        bench("sorted vector + binary search (C)", [] {}, [&](std::string_view q) { return t.search(q); }, queries);
    }
    {
        TrieD t;
        for (auto &d : domains)
            t.insert(d);
        bench("vector + linear search       (D)", [] {}, [&](std::string_view q) { return t.search(q); }, queries);
    }

    return 0;
}