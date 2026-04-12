// bench_trie_vs_dat.cpp
// cl /O2 /std:c++20 /arch:AVX2 bench_trie_vs_dat.cpp
#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <deque>
#include <iostream>
#include <memory>
#include <nmmintrin.h>
#include <queue>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

// ─────────────────────────────────────────────────────
// 公共：CRC32 hasher for string_view
// ─────────────────────────────────────────────────────
struct SvCRC32
{
    size_t operator()(std::string_view sv) const noexcept
    {
        const char *p   = sv.data();
        size_t      n   = sv.size();
        uint64_t    crc = 0;
        while (n >= 8)
        {
            crc = _mm_crc32_u64(crc, *(const uint64_t *)p);
            p += 8;
            n -= 8;
        }
        while (n >= 4)
        {
            crc = _mm_crc32_u32(crc, *(const uint32_t *)p);
            p += 4;
            n -= 4;
        }
        while (n >= 2)
        {
            crc = _mm_crc32_u16(crc, *(const uint16_t *)p);
            p += 2;
            n -= 2;
        }
        if (n)
        {
            crc = _mm_crc32_u8(crc, *(const uint8_t *)p);
        }
        return (size_t)crc;
    }
};

// ─────────────────────────────────────────────────────
// 公共：标签分割（复用现有逻辑）
// ─────────────────────────────────────────────────────
static void split_reverse(std::string_view domain, std::array<std::string_view, 8> &out, int &cnt)
{
    cnt        = 0;
    size_t end = domain.size();
    while (end > 0 && cnt < 8)
    {
        size_t s = domain.find_last_of('.', end - 1);
        if (s == std::string_view::npos)
        {
            out[cnt++] = domain.substr(0, end);
            break;
        }
        out[cnt++] = domain.substr(s + 1, end - s - 1);
        end        = s;
    }
}

// ═════════════════════════════════════════════════════
// 方案 A：散堆 Trie + CRC32 unordered_map（当前实现最优版）
// ═════════════════════════════════════════════════════
struct NodeA
{
    std::unordered_map<std::string_view, std::unique_ptr<NodeA>, SvCRC32> children;
    bool                                                                  is_end = false;
};

struct TrieA
{
    std::unique_ptr<NodeA>  root = std::make_unique<NodeA>();
    std::deque<std::string> storage;

    void insert(const std::string &d)
    {
        storage.push_back(d);
        std::array<std::string_view, 8> lbl;
        int                             cnt;
        split_reverse(storage.back(), lbl, cnt);
        NodeA *cur = root.get();
        for (int i = 0; i < cnt; ++i)
        {
            auto &c = cur->children[lbl[i]];
            if (!c)
                c = std::make_unique<NodeA>();
            cur = c.get();
        }
        cur->is_end = true;
    }

    bool search(std::string_view d) const
    {
        std::array<std::string_view, 8> lbl;
        int                             cnt;
        split_reverse(d, lbl, cnt);
        const NodeA *cur = root.get();
        for (int i = 0; i < cnt; ++i)
        {
            auto it = cur->children.find(lbl[i]);
            if (it == cur->children.end())
                return false;
            cur = it->second.get();
            if (cur->is_end)
                return true;
        }
        return cur->is_end;
    }
};

// ═════════════════════════════════════════════════════
// 方案 B：BFS Arena Trie + CRC32 unordered_map
//   节点存 uint32_t 索引，BFS 重排后父子节点物理相邻
// ═════════════════════════════════════════════════════
static constexpr uint32_t NULL_IDX = UINT32_MAX;

struct NodeB
{
    // value 是 arena 数组的索引，不是指针
    std::unordered_map<std::string_view, uint32_t, SvCRC32> children;
    bool                                                    is_end = false;
};

struct TrieB
{
    std::vector<NodeB>      arena; // 所有节点在连续内存里
    std::deque<std::string> storage;
    bool                    built = false;

    TrieB()
    {
        arena.reserve(1 << 20);
        arena.emplace_back();
    } // arena[0] = root

    void insert(const std::string &d)
    {
        storage.push_back(d);
        std::array<std::string_view, 8> lbl;
        int                             cnt;
        split_reverse(storage.back(), lbl, cnt);
        uint32_t cur = 0;
        for (int i = 0; i < cnt; ++i)
        {
            auto it = arena[cur].children.find(lbl[i]);
            if (it == arena[cur].children.end())
            {
                uint32_t nidx = (uint32_t)arena.size();
                arena.emplace_back();
                // emplace_back 可能 realloc，必须重新取引用
                arena[cur].children[lbl[i]] = nidx;
                cur                         = nidx;
            }
            else
            {
                cur = it->second;
            }
        }
        arena[cur].is_end = true;
    }

    // BFS 重排：把 arena 按广度优先顺序重新排列
    // 父节点总在子节点前面，且同层节点物理相邻
    void build()
    {
        size_t                n = arena.size();
        std::vector<uint32_t> old2new(n, NULL_IDX);
        std::vector<NodeB>    new_arena;
        new_arena.reserve(n);

        std::queue<uint32_t> q;
        q.push(0);
        old2new[0] = 0;
        new_arena.push_back(std::move(arena[0]));

        while (!q.empty())
        {
            uint32_t old_idx = q.front();
            q.pop();
            uint32_t new_idx = old2new[old_idx];
            // arena[old_idx] 已经被 move 走，用 new_arena[new_idx]
            for (auto &[k, child_old] : new_arena[new_idx].children)
            {
                uint32_t child_new = (uint32_t)new_arena.size();
                old2new[child_old] = child_new;
                new_arena.push_back(std::move(arena[child_old]));
                q.push(child_old);
                // 修正索引（转换为新索引）
                const_cast<uint32_t &>(child_old) = child_new;
            }
        }
        arena = std::move(new_arena);
        built = true;
    }

    bool search(std::string_view d) const
    {
        std::array<std::string_view, 8> lbl;
        int                             cnt;
        split_reverse(d, lbl, cnt);
        uint32_t cur = 0;
        for (int i = 0; i < cnt; ++i)
        {
            auto it = arena[cur].children.find(lbl[i]);
            if (it == arena[cur].children.end())
                return false;
            cur = it->second;
            if (arena[cur].is_end)
                return true;
        }
        return arena[cur].is_end;
    }
};

// ═════════════════════════════════════════════════════
// 方案 C：双数组 Trie（字符级 DAT）
//   base[s] + c → next，check[next] == s 则合法
//   支持父域名匹配语义（遇到 '.' 且是 accepting state 即命中）
// ═════════════════════════════════════════════════════
class DAT
{
    // 字符映射：只需要 a-z, 0-9, '-', '.'，共 39 个字符 + 哨兵
    // 用简单方式：直接用 uint8_t 值，alphabet size = 128（ASCII 可见字符子集）
    static constexpr int     ALPHA = 128;
    static constexpr int32_t NONE  = -1;

    std::vector<int32_t> base_;
    std::vector<int32_t> check_;
    std::vector<bool>    is_end_;

    // 构建用临时结构：普通 Trie 先建好再转 DAT
    struct BuildNode
    {
        std::array<int, ALPHA> ch;
        bool                   is_end = false;
        BuildNode() { ch.fill(-1); }
    };
    std::vector<BuildNode> nodes_;
    int                    new_node()
    {
        nodes_.emplace_back();
        return (int)nodes_.size() - 1;
    }

public:
    DAT() {}

    // 插入阶段：先建普通字符级 Trie（仅用于构建，查询时不用）
    void insert(const std::string &domain)
    {
        if (nodes_.empty())
            new_node(); // root = 0

        // 反转域名：存 "moc.elpmaxe.www" 形式
        std::string rev;
        rev.reserve(domain.size());
        // 按标签反转（不是逐字符反转）：com.example.www → 逐字符原样组装反转后的标签序列
        // 更简单：直接逐字符处理反转字符串，标签边界加 '.'
        std::array<std::string_view, 8> lbl;
        int                             cnt;
        split_reverse(domain, lbl, cnt);
        for (int i = 0; i < cnt; ++i)
        {
            if (i)
                rev += '.';
            rev += lbl[i];
        }

        int cur = 0;
        for (unsigned char c : rev)
        {
            if (nodes_[cur].ch[c] == -1)
            {
                nodes_[cur].ch[c] = new_node();
            }
            cur = nodes_[cur].ch[c];
        }
        nodes_[cur].is_end = true;
        // 父域名匹配：example.com 被存为 "com.example"，
        // 查询 www.example.com 时遍历到 "com.example" 末尾发现 is_end，命中
        // 所以 is_end 标记正好对应父域名节点，无需额外处理
    }

    // 构建 DAT：从普通 Trie 转换
    void build()
    {
        int n_nodes = (int)nodes_.size();
        // 初始化 base/check 数组，大小估算为节点数 × ALPHA / 稀疏度
        // 先开 2× 节点数，不够再扩
        int sz = n_nodes * 4 + ALPHA * 2;
        base_.assign(sz, 0);
        check_.assign(sz, NONE);
        is_end_.assign(sz, false);

        // BFS 转换
        // 对每个节点，找到 base 值使得所有子节点 base[node]+c 不冲突
        std::vector<int> node2state(n_nodes, -1);
        node2state[0] = 0;
        base_[0]      = 1; // root 的 base 从 1 开始

        std::queue<int> q;
        q.push(0);

        while (!q.empty())
        {
            int node = q.front();
            q.pop();
            int state = node2state[node];

            // 收集该节点所有有效子字符
            std::vector<int> chars;
            for (int c = 0; c < ALPHA; ++c)
                if (nodes_[node].ch[c] != -1)
                    chars.push_back(c);

            if (chars.empty())
            {
                is_end_[state] = nodes_[node].is_end;
                continue;
            }

            // 找到合适的 base 值：base[state] + c 对所有 c 均未被 check 占用
            int b = 1;
            while (true)
            {
                bool ok = true;
                for (int c : chars)
                {
                    int next = b + c;
                    if (next >= (int)check_.size())
                    {
                        // 扩容
                        int new_sz = next * 2 + ALPHA;
                        base_.resize(new_sz, 0);
                        check_.resize(new_sz, NONE);
                        is_end_.resize(new_sz, false);
                    }
                    if (check_[next] != NONE)
                    {
                        ok = false;
                        break;
                    }
                }
                if (ok)
                    break;
                ++b;
            }

            base_[state]   = b;
            is_end_[state] = nodes_[node].is_end;

            for (int c : chars)
            {
                int next               = b + c;
                check_[next]           = state;
                int child_node         = nodes_[node].ch[c];
                node2state[child_node] = next;
                q.push(child_node);
            }
        }
        nodes_.clear();
        nodes_.shrink_to_fit(); // 释放构建用临时存储
    }

    bool search(std::string_view domain) const
    {
        // 拼出反转后的字符串（按标签）
        std::array<std::string_view, 8> lbl;
        int                             cnt;
        split_reverse(domain, lbl, cnt);

        int cur = 0;
        for (int i = 0; i < cnt; ++i)
        {
            // 先走标签内的字符
            for (unsigned char c : lbl[i])
            {
                int next = base_[cur] + c;
                if (next < 0 || next >= (int)check_.size() || check_[next] != cur)
                    return false;
                cur = next;
            }
            // 走完一个标签，检查父域名匹配
            if (is_end_[cur])
                return true;
            // 如果还有下一个标签，走 '.' 边
            if (i + 1 < cnt)
            {
                int next = base_[cur] + (unsigned char)'.';
                if (next < 0 || next >= (int)check_.size() || check_[next] != cur)
                    return false;
                cur = next;
            }
        }
        return is_end_[cur];
    }

    size_t memory_bytes() const { return (base_.size() + check_.size()) * sizeof(int32_t) + is_end_.size() * sizeof(bool); }
};

// ─────────────────────────────────────────────────────
// 数据生成（写实分布，复用上次结论）
// ─────────────────────────────────────────────────────
static std::vector<std::string> make_domains(int n)
{
    std::array<const char *, 20> tlds = {"com", "net", "org", "io", "co", "ru", "cn", "de", "uk", "fr",
                                         "jp",  "br",  "au",  "in", "ca", "mx", "es", "it", "nl", "se"};
    std::vector<std::string>     v;
    v.reserve(n);
    int flat = n * 6 / 10;
    for (int i = 0; i < flat; ++i)
        v.push_back("domain" + std::to_string(i) + "." + tlds[i % tlds.size()]);
    int one_sub = n * 25 / 100;
    for (int i = 0; i < one_sub; ++i)
        v.push_back("sub" + std::to_string(i % 5) + ".domain" + std::to_string(i / 5) + "." + tlds[(i / 5) % tlds.size()]);
    int rem = n - (int)v.size();
    for (int i = 0; i < rem; ++i)
        v.push_back("svc" + std::to_string(i % 3) + ".sub" + std::to_string(i % 5) + ".domain" + std::to_string(i / 15) + "." +
                    tlds[(i / 15) % tlds.size()]);
    return v;
}

// ─────────────────────────────────────────────────────
// 正确性验证：三者结果必须完全一致
// ─────────────────────────────────────────────────────
static void verify(TrieA &a, TrieB &b, DAT &c, const std::vector<std::string> &queries)
{
    int mismatches = 0;
    for (auto &q : queries)
    {
        bool ra = a.search(q), rb = b.search(q), rc = c.search(q);
        if (ra != rb || ra != rc)
        {
            ++mismatches;
            if (mismatches <= 5)
                std::cout << "[MISMATCH] \"" << q << "\"  A=" << ra << " B=" << rb << " C=" << rc << "\n";
        }
    }
    if (mismatches == 0)
        std::cout << "[OK] All " << queries.size() << " queries agree across A/B/C\n\n";
    else
        std::cout << "[FAIL] " << mismatches << " mismatches!\n\n";
}

// ─────────────────────────────────────────────────────
// 基准框架
// ─────────────────────────────────────────────────────
template <typename SearchFn>
void bench(const char *name, SearchFn &&fn, const std::vector<std::string> &queries)
{
    constexpr int ITERS = 5'000'000;
    volatile int  dummy = 0;
    // warm-up
    for (int i = 0; i < 20000; ++i)
        dummy += fn(queries[i % queries.size()]) ? 1 : 0;

    auto t0 = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < ITERS; ++i)
        dummy += fn(queries[i % queries.size()]) ? 1 : 0;
    auto t1 = std::chrono::high_resolution_clock::now();

    double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    printf("%-45s %7.1f ms   %4lld M ops/s  [d=%d]\n", name, ms, (long long)(ITERS / (ms / 1000.0) / 1e6), (int)dummy);
}

int main()
{
    constexpr int N       = 100'000;
    auto          domains = make_domains(N);

    // 查询集：50% 命中（黑名单直接匹配）+ 25% 子域名命中 + 25% miss
    std::vector<std::string> queries;
    queries.reserve(12000);
    for (int i = 0; i < 3000; ++i)
        queries.push_back(domains[i]); // 直接命中
    for (int i = 0; i < 3000; ++i)
        queries.push_back("x.x." + domains[i]); // 子域名命中（父域名语义）
    for (int i = 0; i < 3000; ++i)
        queries.push_back(domains[N / 2 + i]); // 命中（黑名单后半段）
    for (int i = 0; i < 3000; ++i)
        queries.push_back("miss" + std::to_string(i) + ".xyz"); // miss

    // ── 构建阶段 ────────────────────────────────────────────────────
    std::cout << "=== Building ===\n";
    TrieA ta;
    {
        auto t0 = std::chrono::high_resolution_clock::now();
        for (auto &d : domains)
            ta.insert(d);
        auto t1 = std::chrono::high_resolution_clock::now();
        printf("A (heap Trie + CRC32):        build = %.1f ms\n", std::chrono::duration<double, std::milli>(t1 - t0).count());
    }

    TrieB tb;
    {
        auto t0 = std::chrono::high_resolution_clock::now();
        for (auto &d : domains)
            tb.insert(d);
        tb.build(); // BFS 重排
        auto t1 = std::chrono::high_resolution_clock::now();
        printf("B (BFS arena Trie + CRC32):   build = %.1f ms\n", std::chrono::duration<double, std::milli>(t1 - t0).count());
    }

    DAT tc;
    {
        auto t0 = std::chrono::high_resolution_clock::now();
        for (auto &d : domains)
            tc.insert(d);
        tc.build();
        auto t1 = std::chrono::high_resolution_clock::now();
        printf("C (DAT):                      build = %.1f ms\n", std::chrono::duration<double, std::milli>(t1 - t0).count());
        printf("   DAT memory: %.1f MB\n", tc.memory_bytes() / 1024.0 / 1024.0);
    }

    // ── 正确性验证 ───────────────────────────────────────────────────
    std::cout << "\n=== Correctness ===\n";
    verify(ta, tb, tc, queries);

    // ── 查询性能 ─────────────────────────────────────────────────────
    std::cout << "=== Query throughput (build excluded) ===\n";
    bench("A: heap Trie + CRC32 unordered_map", [&](std::string_view q) { return ta.search(q); }, queries);
    bench("B: BFS arena Trie + CRC32 unordered_map", [&](std::string_view q) { return tb.search(q); }, queries);
    bench("C: DAT (double-array trie)", [&](std::string_view q) { return tc.search(q); }, queries);

    return 0;
}