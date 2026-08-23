# DNS_PRO MVP 范围与行为约定

本文档固定 DNS_PRO 第一版可运行产品的边界。后续实现和测试以此为准；变更这些语义时，应先更新本文档和对应测试。

## 产品定位

DNS_PRO 第一版是运行在 Linux 上的过滤型 DNS 转发器，不是权威 DNS 服务器，也不自行执行完整的递归解析。

服务使用多个彼此独立的 worker 处理数据面流量。每个 worker 拥有自己的监听 socket、上游 socket、事件循环、查询等待表和缓存分片。控制面负责加载配置及构建不可变的过滤上下文。

## 第一版支持范围

- 下游客户端通过 UDP 查询。
- 通过 UDP 向一个可配置的上游 DNS 服务器转发查询。
- 下游查询、上游查询和下游/上游响应都遵守经典 UDP DNS 的 512 字节 payload 上限；该限制属于服务传输策略，不是通用 DNS wire parser 的全局上限。
- 支持 `A` 和 `AAAA` 查询的解析、过滤、转发及正缓存。
- 无法解析但至少包含 transaction ID 的查询报文返回 `FORMERR`；更短的报文直接丢弃。
- 格式合法但 MVP 不支持的 opcode、QTYPE、QCLASS 或扩展返回 `NOTIMP`。
- 所有本地响应都受 512 字节预算约束；错误响应无法连同 question 装入预算时退化为保留 ID、opcode、RD、CD 和目标 RCODE 的 header-only 响应，所有 section count 为零且 `AD=0`。最终发送入口再次拒绝任何 oversized 响应。
- 下游收到大于 512 字节的查询时，只读取固定头部前缀并返回 header-only `FORMERR`；大于 512 字节且 `QR=1` 的数据报静默丢弃。被截断的部分报文不得进入完整 parser。
- 上游收到大于 512 字节的响应时丢弃该数据报，但保持原 pending query 继续等待；若没有后续合法响应，再按原 deadline 超时并返回 `SERVFAIL`。
- 上游超时或网络失败返回 `SERVFAIL`。
- 命中过滤规则时返回 `REFUSED`，并保留客户端 transaction ID 和原始 question。
- 服务采用一次性生命周期：初始化失败可修正配置后重试；一旦尝试启动，成功停止或启动失败后都必须构造新对象。启动只有在全部必需控制角色和 worker Ready、activation ack 完成且统一 data-plane gate 打开后才成功。
- 服务支持显式启动、停止和等待结构化退出结果；停止时取消尚未完成的上游查询。启动失败或运行期 fatal 使可执行程序非零退出。
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

## 过滤规则热更新语义

- 运行期更新是对完整规则集合的替换，不是单条规则的原地增删。
- 初始过滤快照的 generation 为 1；每次成功发布严格增加 1。构建失败、取消或 generation 耗尽均不改变当前 generation。
- generation、Cuckoo Filter 和精确 RadixTree 位于同一个不可变快照中，并通过一个原子交换同时发布。不得将两种索引分别发布。
- 控制面按提交顺序串行构建候选快照。候选完整构建成功后才允许发布；任一规则非法时，旧快照对象和过滤行为保持不变。
- 同步更新接口返回成功后，随后进入过滤阶段的请求必须看到新快照。已经通过旧快照过滤并等待上游的请求可以按旧决定完成。
- 停止过程不再接受新更新；排队或仍在构建但尚未发布的更新必须得到明确的取消结果，不能在停止后覆盖快照。
- 控制面更新队列最多暂存 64 个命令；单次完整替换最多包含 100,000 条规则、原始/规范化规则数据最多 16 MiB，排队命令的原始规则数据合计最多 64 MiB。任一上限在重型构建前检查并立即返回结构化错误，避免完整规则集合无界积压。已编译唯一规则的 canonical wire-key 字节数用于 retired-byte 记账；它是受控的 accounted bytes，不等同于精确 RSS。
- `runtime_updates_enabled=false` 允许静态过滤但不创建更新协调线程 A 或回收线程 B，并明确拒绝运行期更新；`true` 启用唯一串行 A 和专用 B。worker 生命周期由独立的 supervisor C 管理，不能通过“多个 manager”配置复制控制角色。
- 配置中的原始规则字符串仅作为启动输入；已发布的数据面状态只持有编译后的不可变快照，控制面可在命令排队和构建期间暂存一份 owned rules。
- active snapshot 的原子 exchange 是不可逆 commit point。commit 前的停止返回取消且 generation 不变；commit 后的调用继续等待该次发布固定捕获的 exact worker cohort，不能声称回滚或取消。
- 每个 worker 只在自身线程的 generation 安全点切换本地 `shared_ptr<const FilterContext>`；请求热路径只读该本地快照，不执行 per-request atomic shared_ptr load 或引用计数。过滤匹配同步结束，任何树内指针、引用或迭代器都不得跨越上游查询的 `co_await`。
- publication 在低频 mutex 下与 participant 注册线性化，并固定捕获 `(worker_id, instance_id, WorkerEpoch*)`。B 只接受同一 exact token 的 generation ack，或 C 在 join、销毁 WorkerLoop 并释放本地 snapshot 后发布的 quiescence；Exited、心跳或从 active 列表移除都不是回收证明。
- 同一时刻最多有一个普通 retired generation。稳定 retirement record 始终持有旧 owner；完整 cohort 收敛后先完成已 commit future，随后由 B 析构 sole old owner并归还 credit，因此同步 API 不承担析构尾延迟，而下一次重型构建仍受背压。最终 active owner 使用独立 terminal record。30 秒 grace timeout 只产生包含 pending token/observed generation/accounted bytes 的 fatal 诊断，绝不强制回收。

## 缓存语义

缓存键至少包含：

```text
canonical QNAME + QTYPE + QCLASS
```

- 第一版只缓存成功的 `A` 和 `AAAA` 正响应。
- 地址缓存以完整的直接 `A`/`AAAA` RRset 为值，并以 RRset 中最小 TTL 作为统一缓存期限；不会只截取多地址响应中的第一条记录。
- 第一版不会把 `CNAME` 链改写为直接地址答案。包含别名链或无法由地址 RRset 无损重建的 authority/additional 数据时，响应仍透明转发，但不进入缓存。
- 带 `CD` 或 `AD` DNSSEC 控制位的查询透明转发但绕过地址缓存，避免与普通查询共享未经验证或验证语义不同的结果。
- 下游查询的 `AD`/`CD` 原样转发，上游响应的 `AD`/`CD` 原样返回。本地产生的 error/cache response 不设置 `AD`，但按 writer 契约保留 query 的 `CD`。
- 合法但设置 `TC=1` 的上游响应透明返回且不进入正缓存；第一版不尝试 TCP fallback。
- 缓存采用上游响应中的实际 TTL，并使用单调时钟判断过期。
- 返回缓存响应时必须恢复当前客户端的 transaction ID，并反映剩余 TTL。
- 缓存 RRset 若无法在 512 字节内无损重建，则该次访问按 cache miss 处理并只向上游发送一次查询，不能发送半截缓存响应。
- 第一版不实现 `NXDOMAIN`、NODATA 等负缓存。
- 过滤检查先于缓存查询，规则更新后不能因为旧缓存而绕过过滤。

## 并发与所有权约定

- 每个 worker 独占自己的 cache shard 和 pending-query table，热路径不依赖跨 worker 锁。
- 上游 transaction ID 在 worker 自己的上游 socket 命名空间内分配。
- transaction ID 从随机化的空闲池分配；完成后的 ID 至少隔离一个查询超时窗口后才可复用。重复或迟到响应在该隔离窗口内不得命中新查询；窗口之外的无限迟到包不属于 UDP DNS 能够提供的保证。
- 协程只能由所属 worker 的 scheduler 恢复。
- 响应、超时、取消和网络错误只能有一个成为等待操作的最终完成原因。
- coroutine frame、文件描述符、定时器和 pending query 必须具有明确且可测试的 owner。
- 过滤规则在控制面完整构建后，以不可变快照形式原子发布；A 只向 C 发送 generation 事件，C 用独立 eventfd 唤醒空闲 worker。Ready/activation/data-plane gate 同样能返回 Refresh 动作，避免 Starting participant 因尚未进入 epoll 而阻塞 grace period。
- 初始启动是 all-or-nothing；B、A、C 和全部 worker Ready 后，worker 依次通过 activation gate 并停在 data-plane gate，服务提交 Active 前不能处理数据报。阶段 13 仍将运行期 worker 意外退出升级为完整服务失败；配置化的进程内重启在阶段 14 启用。
- 正常停止先 seal publication，再由 C join/reset worker，随后完成 committed cohort；C 执行线程可以在 drain 后先 join，但 DNS-owned WorkerRecord registry 必须继续存活。A detach terminal owner 后退出，B 析构所有 stable owner，最后才销毁 registry。A/B/C 任一故障时，外部 teardown coordinator 只有在 join 对应的原唯一 writer 后才能接管，并且仍须用 exact ack/quiescence 证明安全；若 DNS 析构时仍无法证明所有 worker 已 join，则 fail-fast而不能冒险释放 owner。

## 第一版明确不支持

- 下游或上游 DNS over TCP。
- UDP 响应截断后的 TCP fallback。
- 任何 EDNS/OPT 协商或扩展选项。DNS RR 外壳完整的 OPT/additional query 返回 `NOTIMP`；RR 外壳截断、RDLENGTH 越界或 section/trailing 不一致返回 `FORMERR`，OPT RDATA 内部 option tuple 保持 opaque。
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
3. `dig +noedns` 可以通过 DNS_PRO 完成未命中过滤规则的 A/AAAA 查询；带合法 OPT 的原始查询首包直接得到 `NOTIMP`，不能依赖客户端 fallback 掩盖行为。
4. 缓存命中不访问上游，且 A 与 AAAA 不会互相覆盖。
5. 父域过滤规则能够拦截其子域，命中时返回 `REFUSED`。
6. 上游响应乱序、重复、迟到或超时时不会串包或重复恢复协程。
7. 服务能够在存在未完成查询时正常停止，无 fd、协程帧或 pending-query 泄漏。
8. ASan/UBSan 测试和基础并发压测不报告内存或未定义行为错误。
9. 合法规则热更新以完整 generation 生效；非法、取消或停止中的更新不会改变现有过滤行为。
