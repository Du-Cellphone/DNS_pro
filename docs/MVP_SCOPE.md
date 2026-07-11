# DNS_PRO MVP 范围与行为约定

本文档固定 DNS_PRO 第一版可运行产品的边界。后续实现和测试以此为准；变更这些语义时，应先更新本文档和对应测试。

## 产品定位

DNS_PRO 第一版是运行在 Linux 上的过滤型 DNS 转发器，不是权威 DNS 服务器，也不自行执行完整的递归解析。

服务使用多个彼此独立的 worker 处理数据面流量。每个 worker 拥有自己的监听 socket、上游 socket、事件循环、查询等待表和缓存分片。控制面负责加载配置及构建不可变的过滤上下文。

## 第一版支持范围

- 下游客户端通过 UDP 查询。
- 通过 UDP 向一个可配置的上游 DNS 服务器转发查询。
- 支持 `A` 和 `AAAA` 查询的解析、过滤、转发及正缓存。
- 无法解析的报文返回 `FORMERR`。
- 上游超时或网络失败返回 `SERVFAIL`。
- 命中过滤规则时返回 `REFUSED`，并保留客户端 transaction ID 和原始 question。
- 服务支持显式启动、停止和等待退出；停止时取消尚未完成的上游查询。
- 每个请求从接收到完成固定在同一个 worker 线程上，不在 worker 之间迁移。

## 域名规范化与过滤语义

业务层中的域名统一使用以下规范形式：

- ASCII 字母转换为小写。
- 移除表示 DNS 根的末尾 `.`。
- 不在第一版中执行 Unicode/IDNA 转换；输入按 DNS wire format 中的字节处理。

过滤规则采用“精确域及其子域”语义：

- 规则 `example.com` 匹配 `example.com`。
- 规则 `example.com` 匹配 `www.example.com`。
- 规则 `www.example.com` 不匹配 `example.com`。
- 第一版不支持 `*`、`?`、正则表达式或例外规则。

Cuckoo Filter 只能作为 RadixTree 前置加速结构，不能改变上述匹配结果，尤其不能造成 false negative。

## 缓存语义

缓存键至少包含：

```text
canonical QNAME + QTYPE + QCLASS
```

- 第一版只缓存成功的 `A` 和 `AAAA` 正响应。
- 缓存采用上游响应中的实际 TTL，并使用单调时钟判断过期。
- 返回缓存响应时必须恢复当前客户端的 transaction ID，并反映剩余 TTL。
- 第一版不实现 `NXDOMAIN`、NODATA 等负缓存。
- 过滤检查先于缓存查询，规则更新后不能因为旧缓存而绕过过滤。

## 并发与所有权约定

- 每个 worker 独占自己的 cache shard 和 pending-query table，热路径不依赖跨 worker 锁。
- 上游 transaction ID 在 worker 自己的上游 socket 命名空间内分配。
- 协程只能由所属 worker 的 scheduler 恢复。
- 响应、超时、取消和网络错误只能有一个成为等待操作的最终完成原因。
- coroutine frame、文件描述符、定时器和 pending query 必须具有明确且可测试的 owner。
- 过滤规则在控制面完整构建后，以不可变快照形式原子发布。

## 第一版明确不支持

- 下游或上游 DNS over TCP。
- UDP 响应截断后的 TCP fallback。
- EDNS0 的完整协商与所有扩展选项。
- 多上游负载均衡、健康检查和自动故障转移。
- DNSSEC 验证。
- DoT、DoH、DoQ。
- 权威解析、区域文件和完整递归解析。
- 持久化缓存和分布式缓存。
- Unicode 域名到 IDNA/Punycode 的转换。

收到第一版不支持的查询类型时，服务应返回明确的错误响应，而不是构造可能错误的答案。透明转发其他类型属于后续兼容性扩展。

## MVP 验收条件

第一版完成需要同时满足：

1. 全新构建目录能够完成配置、编译和 CTest。
2. DNS parser 对截断、越界和恶意 compression pointer 输入保持内存安全。
3. `dig` 可以通过 DNS_PRO 完成未命中过滤规则的 A/AAAA 查询。
4. 缓存命中不访问上游，且 A 与 AAAA 不会互相覆盖。
5. 父域过滤规则能够拦截其子域，命中时返回 `REFUSED`。
6. 上游响应乱序、重复、迟到或超时时不会串包或重复恢复协程。
7. 服务能够在存在未完成查询时正常停止，无 fd、协程帧或 pending-query 泄漏。
8. ASan/UBSan 测试和基础并发压测不报告内存或未定义行为错误。
