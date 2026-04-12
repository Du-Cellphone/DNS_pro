#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include "RadixTree.h"

std::vector<std::string_view> split_and_reverse(std::string_view domain)
{
    std::vector<std::string_view> labels;
    labels.reserve(8);

    size_t end = domain.length();
    while (end > 0)
    {
        size_t start = domain.find_last_of('.', end - 1);
        if (start == std::string_view::npos)
        {
            labels.emplace_back(domain.substr(0, end));
            break;
        }

        labels.emplace_back(domain.substr(start + 1, end - (start + 1)));
        end = start;
    }
    return labels;
}

void RadixTree::insert(const std::string &domain)
{
    string_storage.push_back(domain);
    std::vector<std::string_view> labels  = split_and_reverse(string_storage.back());
    TrieNode                     *current = root.get();

    // TODO 通配符*和?的处理，目前是直接当成普通字符插入树中
    // TODO 目前是完全匹配，后续可以考虑支持通配符和正则表达式等更复杂的匹配规则
    // TODO 连续的通配符，例如 **.example.com 这种情况如何处理？目前是两个*当作一个标签插入树中
    // TODO 连续的相同单字符标签，例如 a.a.a.a.com，可能会退化为字典树
    // TODO 如果某个标签已经是is_end_of_domain了，那么需不需要剪枝？
    for (std::string_view label : labels)
    {
        if (current->children.find(label) == current->children.end())
            current->children[label] = std::make_unique<TrieNode>();
        current = current->children[label].get();
    }
    current->is_end_of_domain = true;
}

bool RadixTree::search(const std::string &domain) const
{
    std::vector<std::string_view> labels = split_and_reverse(domain);

    TrieNode *current = root.get();
    for (std::string_view label : labels)
    {
        if (current->children.find(label) == current->children.end())
            return false;
        current = current->children[label].get();

        if (current->is_end_of_domain)
            return true; // 适配通配符和子域名，例如 *.example.com 和 example.com 都能匹配到 example.com 和 www.example.com
    }
    return current->is_end_of_domain;
}