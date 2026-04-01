#include <mutex>
#include <array>
#include <memory>
#include <vector>
#include <cstring>
#include <ctime>
#include <algorithm>

#include "DNS_msg.h"

// 替代原C的DNSRecord结构体
struct DNSRecord
{
    static constexpr size_t                      MAX_DOMAIN_LENGTH = 512;
    std::array<unsigned char, MAX_DOMAIN_LENGTH> domain; // 替代字符数组，避免越界
    struct Entry
    {
        std::vector<unsigned char> ip; // RAII管理IP内存，替代malloc/free
        bool                       isAuthority;
    } entry;
    time_t expiry;
    // LRU链表：next_lru持有所有权，prev_lru仅引用
    std::unique_ptr<DNSRecord> next_lru;
    DNSRecord                 *prev_lru = nullptr;
    // 哈希桶链表：next_in_bucket持有所有权
    std::unique_ptr<DNSRecord> next_in_bucket;

    // 构造函数：初始化域名、IP、TTL等，RAII初始化资源
    DNSRecord(const unsigned char *domain, const unsigned char *ip, size_t ip_len, time_t expiry,
              bool authority)
    {
        std::strncpy(reinterpret_cast<char *>(this->domain.data()),
                     reinterpret_cast<const char *>(domain), MAX_DOMAIN_LENGTH - 1);
        this->domain[MAX_DOMAIN_LENGTH - 1] = '\0'; // 确保终止符
        this->entry.ip.assign(ip, ip + ip_len);     // vector自动拷贝+管理内存
        this->entry.isAuthority = authority;
        this->expiry            = expiry;
    }
};



// 哈希桶结构（简化，用unique_ptr管理节点）
struct DNSBucket
{
    std::unique_ptr<DNSRecord> head;
    size_t                     length = 0;
};

class DNSCache
{
public:
    static constexpr size_t TABLE_SIZE        = 667000;
    static constexpr size_t MAX_DOMAIN_LENGTH = 512;

    // 构造函数：替代InitCache，RAII初始化
    DNSCache()
        : max_size(TABLE_SIZE)
        , total_size(0)
        , lru_tail(nullptr)
    {
        // 哈希桶默认初始化即可，无需memset
    }

    // 析构函数：替代ClearCache+DestroyCache，自动清理所有资源
    ~DNSCache()
    {
        // 无需手动free，unique_ptr会自动销毁所有节点
        // 哈希桶的unique_ptr自动释放，LRU链表的unique_ptr也会递归释放
        total_size = 0;
    }

    // 禁用拷贝（避免浅拷贝导致的double free）
    DNSCache(const DNSCache &)            = delete;
    DNSCache &operator=(const DNSCache &) = delete;

    // 移动语义（可选，按需开启）
    DNSCache(DNSCache &&) noexcept            = default;
    DNSCache &operator=(DNSCache &&) noexcept = default;

    // 插入缓存（替代原InsertCache）
    bool insert(const unsigned char *domain, const unsigned char *ip, unsigned int TTL,
                unsigned short type, bool authority)
    {
        if (!domain || !ip)
            return false;

        std::lock_guard<std::mutex> lock(mtx); // RAII加锁，析构自动解锁

        const size_t ip_len = (type == TYPE_A) ? 4 : 16;
        const size_t index =
            murMurHash(domain, std::strlen(reinterpret_cast<const char *>(domain)));

        // 用unique_ptr管理新节点，即使后续失败也会自动释放
        auto new_node =
            std::make_unique<DNSRecord>(domain, ip, ip_len, time(nullptr) + TTL, authority);
        if (!new_node)
            return false;

        // 插入哈希桶（替代原裸指针操作）
        new_node->next_in_bucket = std::move(buckets[index].head); // 转移所有权
        buckets[index].head      = std::move(new_node);
        buckets[index].length++;

        // 更新LRU（封装到私有方法）
        moveToLRUHead(buckets[index].head.get());
        total_size++;

        // 超出最大容量时清理LRU尾部（替代原手动free）
        evictIfOverMaxSize();

        return true;
    }

    // 查询缓存（替代原FindInCache）
    bool find(const unsigned char *domain, std::vector<unsigned char> &ip_out, unsigned short type,
              bool &authority)
    {
        if (!domain)
            return false;

        std::lock_guard<std::mutex> lock(mtx); // RAII加锁

        const size_t index =
            murMurHash(domain, std::strlen(reinterpret_cast<const char *>(domain)));
        DNSRecord *current = buckets[index].head.get();

        while (current)
        {
            if (_stricmp(reinterpret_cast<const char *>(current->domain.data()),
                         reinterpret_cast<const char *>(domain)) == 0)
            {
                // 校验类型
                const bool valid = (type == TYPE_A && current->entry.ip.size() == 4) ||
                                   (type == TYPE_AAAA && current->entry.ip.size() == 16);
                if (!valid)
                    return false;

                // 更新LRU（移到头部）
                moveToLRUHead(current);
                // 更新过期时间
                current->expiry = time(nullptr) + 60;
                // 输出IP（vector自动管理）
                ip_out    = current->entry.ip;
                authority = current->entry.isAuthority;
                return true;
            }
            current = current->next_in_bucket.get();
        }
        return false;
    }

    // 清理过期缓存（替代原RefreshCache）
    void refresh()
    {
        std::lock_guard<std::mutex> lock(mtx);
        const time_t                now = time(nullptr);

        while (lru_tail && lru_tail->expiry < now)
        {
            DNSRecord *expired = lru_tail;
            lru_tail           = expired->prev_lru;

            // 从哈希桶移除（封装到私有方法）
            removeFromBucket(expired);

            // 从LRU链表移除（无需free，unique_ptr自动释放）
            if (expired->prev_lru)
            {
                expired->prev_lru->next_lru.reset();
            }
            else
            {
                // 只剩这一个节点
                lru_tail = nullptr;
            }

            total_size--;
        }
    }

private:
    std::array<DNSBucket, TABLE_SIZE> buckets;              // 哈希桶数组
    std::unique_ptr<DNSRecord>        lru_head;             // LRU头节点（持有所有权）
    DNSRecord                        *lru_tail   = nullptr; // LRU尾节点（仅引用）
    size_t                            total_size = 0;
    size_t                            max_size;
    std::mutex                        mtx; // 替代CRITICAL_SECTION，RAII管理

    // MurMurHash保持逻辑不变，改为私有成员函数
    size_t murMurHash(const void *key, int len)
    {
        const unsigned int   m    = 0x5bd1e995;
        const int            r    = 24;
        const int            seed = 97;
        unsigned int         h    = seed ^ len;
        const unsigned char *data = static_cast<const unsigned char *>(key);
        while (len >= 4)
        {
            unsigned int k = *reinterpret_cast<const unsigned int *>(data);
            k *= m;
            k ^= k >> r;
            k *= m;
            h *= m;
            h ^= k;
            data += 4;
            len -= 4;
        }
        switch (len)
        {
            case 3:
                h ^= data[2] << 16;
            case 2:
                h ^= data[1] << 8;
            case 1:
                h ^= data[0];
                h *= m;
        };
        h ^= h >> 13;
        h *= m;
        h ^= h >> 15;
        return h % TABLE_SIZE;
    }

    // 私有方法：将节点移到LRU头部（封装指针操作）
    void moveToLRUHead(DNSRecord *node)
    {
        if (node == lru_head.get())
            return;

        // 从原LRU位置移除
        if (node->prev_lru)
        {
            node->prev_lru->next_lru = std::move(node->next_lru);
            if (node->next_lru)
            {
                node->next_lru->prev_lru = node->prev_lru;
            }
        }
        if (node == lru_tail)
        {
            lru_tail = node->prev_lru;
        }

        // 插入到LRU头部
        node->next_lru = std::move(lru_head);
        if (lru_head)
        {
            lru_head->prev_lru = node;
        }
        lru_head.reset(node); // 转移所有权到lru_head
        node->prev_lru = nullptr;

        // 初始化LRU尾（如果是空的）
        if (!lru_tail)
        {
            lru_tail = node;
        }
    }

    // 私有方法：从哈希桶移除节点（封装指针操作）
    void removeFromBucket(DNSRecord *node)
    {
        const size_t index = murMurHash(
            node->domain.data(), std::strlen(reinterpret_cast<const char *>(node->domain.data())));
        DNSBucket &bucket = buckets[index];

        if (bucket.head.get() == node)
        {
            bucket.head = std::move(node->next_in_bucket);
        }
        else
        {
            DNSRecord *current = bucket.head.get();
            while (current && current->next_in_bucket.get() != node)
            {
                current = current->next_in_bucket.get();
            }
            if (current)
            {
                current->next_in_bucket = std::move(node->next_in_bucket);
            }
        }
        bucket.length--;
    }

    // 私有方法：超出容量时淘汰LRU尾部
    void evictIfOverMaxSize()
    {
        while (total_size > max_size && lru_tail)
        {
            DNSRecord *to_evict = lru_tail;
            lru_tail            = to_evict->prev_lru;

            // 从哈希桶移除
            removeFromBucket(to_evict);

            // 从LRU链表移除
            if (to_evict->prev_lru)
            {
                to_evict->prev_lru->next_lru.reset();
            }
            else
            {
                lru_head.reset();
            }

            total_size--;
        }
    }
};