# 运行期 worker 恢复

阶段 14 通过 `DNSConfig` 开启进程内恢复。当前示例程序 `main.cpp` 仍使用默认 `FailService`；尚未提供命令行或配置文件解析。

```cpp
DNSConfig config;
config.worker_count = 4;
config.port = 5353;
config.runtime_updates_enabled = true;
config.worker_failure_policy = WorkerFailurePolicy::Restart;
config.restart_max_attempts = 3;
config.restart_initial_backoff = std::chrono::milliseconds{100};
config.restart_max_backoff = std::chrono::milliseconds{5'000};
config.restart_stability_window = std::chrono::milliseconds{30'000};
```

`FailService` 是默认策略，任意运行期 worker 异常都会停止完整服务。`Restart` 仅恢复已经进入 Active 的服务中的 worker；初次 create/bind/线程启动/Ready 失败始终使 `start()` 返回错误并完成整体回滚，A/B/C 的异常也始终是服务级 fatal。

下列参数约束在 `Restart` 策略下校验；`FailService` 不使用恢复时长和预算。

| 配置 | 默认值 | 语义 |
| --- | --- | --- |
| `restart_max_attempts` | 3 | 每个 logical worker 在一个恢复周期内最多准入的 replacement 创建次数；Restart 时必须大于零 |
| `restart_initial_backoff` | 100 ms | 首次 replacement 的等待时间，必须非负 |
| `restart_max_backoff` | 5,000 ms | 后续等待按指数增长的上限，不能小于 initial |
| `restart_stability_window` | 30,000 ms | replacement 连续 Running 满此窗口才重置该 worker 的周期预算和退避，必须非负 |

例如预算为 3 时，初始 worker 退出后依次允许 replacement 1、2、3；create/init/bind 失败或 replacement 很快再次退出都消耗这三次额度。第 3 个 replacement 也失败且没有经历稳定窗口时，服务以 `RestartBudgetExhausted` 发起 fatal teardown。短暂 Ready 或 Running 不重置预算。设 stability window 为 0 表示激活后即可满足稳定条件，会降低对反复退出的限制；initial 为 0 则没有重试等待。

退避等待使用 C 的事件循环 deadline。stop 会关闭准入并唤醒等待；规则更新和其他 worker 的 Ready/completion 同样可以唤醒 C。旧 worker 的线程必须 join、WorkerLoop 销毁、本地 snapshot 释放并注销 epoch 后，C 才允许该逻辑槽位复用 cache shard。缓存内容保留，旧实例的 pending query、协程、timer 和 fd 不转移给新实例。

新实例安装 current snapshot、通过 generation 二次校验及独立 Ready/Activate 握手后才开始处理数据报。已结束的 worker 会先关闭 listener，退出 `SO_REUSEPORT` 组。恢复不能保证在途 UDP 请求不丢失，客户端仍需遵循自己的查询超时和重试策略。

## 健康状态和诊断

`DNS::is_running()` 只检查生命周期 Active；它并不保证当前有 worker 可用。应同时读取 `DNS::health()`：

| lifecycle / health | 含义 |
| --- | --- |
| Active / Healthy | 所有目标 worker 已进入 Running |
| Active / Degraded | 至少一个 worker 可用，其他 worker 正在恢复 |
| Active / Unavailable | 暂时没有可用 worker，仍有恢复预算和准入 |
| Stopping / Unavailable | 正常或 fatal 停机正在排空资源 |
| Failed / Unavailable | fatal 或启动失败已完成清理 |

health 的 `available_workers` / `desired_workers` 表示可用量与目标量。`restart_count` 是累计准入创建的次数，`restart_success_count` 是累计激活为 Running 的 replacement 次数，`restart_failure_count` 是 replacement 创建/启动失败或随后异常退出的次数。它们是 lifetime counters，稳定窗口不会清零；同一个 replacement 可以先成功激活再失败，因此 success + failure 不一定等于 attempts。stop 之后仍会收集已经发生的计数，但迟到快照不能把健康状态改回 Healthy。

`last_error` 在恢复 Healthy 后保留最近一次错误；即使其类型名为 `DNSFatalError`，它也可能只是已成功恢复的 worker 故障。通过 lifecycle 和 `join()`/`wait()` 的 `fatal_error` 判断服务是否真正 fatal。错误携带 `worker_id`、`instance_id`、`worker_failure_code`、create/runtime step 以及 errno；预算耗尽保留最后一次失败的细节。跨线程读取的是 C 发布的值快照，不直接读取活动 WorkerLoop 的普通 stats 字段。

`port=0` 仅供初次启动选择端口，之后 `bound_port()` 始终报告被冻结的 `effective_bound_port`，包括恢复和 Failed 状态。replacement 必须重新绑定同一个端口。所有旧 listener 关闭后，其他进程可能占用它；此时真实 `EADDRINUSE` 会计入恢复预算，绝不会静默选择新随机端口。

## 外部恢复边界

进程内恢复只覆盖能结束并可 join 的 worker，不覆盖段错误、内存破坏或永久挂起。join 失败不会注销 epoch、释放尚被借用的 snapshot 或创建 replacement。正常回收和 emergency takeover 都保留这个约束。

`std::jthread::join()` 没有硬超时；未返回的 run、退出清理或 join 可能需要部署侧独立 watchdog 检测长期不可用/恢复停滞并终止进程。grace timeout 也只能触发诊断和 fatal，不能强行回收。若 API 返回 `TeardownIncomplete`，owner 仍被保留，调用者可以重试 join；析构仍未完成清理的 DNS 会 fail-fast，避免释放潜在借用对象。

正常收到停止信号后调用 `request_stop()` 和 `join()`；`wait()` 会等待正常 stop 或服务级 fatal 再驱动收尾，不会仅因暂时 Degraded/Unavailable 就退出。可执行程序在启动失败和 fatal 后非零退出，可由 systemd、容器或其他进程监管器重启。

## 回归验证

`cmake --preset strict-sockets`、`cmake --build --preset strict-sockets`、`ctest --preset strict-sockets` 要求真实 loopback UDP 能力；不能运行 socket 时会明确失败。`dns_recovery_tests` 覆盖恢复中的 UDP、current generation、stale token、预算/稳定窗口/退避、stop 各边界、端口抢占和 join 失败。另提供 `asan`、`ubsan`、`tsan` presets；TSan 运行依赖兼容的宿主机地址空间。
