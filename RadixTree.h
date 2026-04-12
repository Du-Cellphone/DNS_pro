#pragma once

#include <deque>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include "HashUtils.hpp"

std::vector<std::string_view> split_and_reverse(std::string_view domain);

class RadixTree
{
public:
    RadixTree()
        : root(std::make_unique<TrieNode>())
    {
    }
    bool build(); // 从文件/数据库加载数据构建 Radix Tree
    void insert(const std::string &domain);

    bool search(const std::string &domain) const;

private:
    struct TrieNode
    {
        std::unordered_map<std::string_view, std::unique_ptr<TrieNode>, SvCRC32> children;

        bool is_end_of_domain{false};
    };



    std::unique_ptr<TrieNode> root;
    std::deque<std::string>   string_storage; // 用于存储实际的字符串，TrieNode中只保存string_view
};