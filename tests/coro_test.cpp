#include <coroutine>
#include <cstdint>
#include <iostream>
#include <vector>
#include <unordered_map>

struct Task
{
    struct promise_type
    {
        Task get_return_object() { return {}; }

        // 修改这里：使用 std::suspend_always
        std::suspend_always initial_suspend() { return {}; }

        // 修改这里：使用 std::suspend_always
        std::suspend_always final_suspend() noexcept { return {}; }

        void return_void() {}
        void unhandled_exception() {}
    };
};

std::unordered_map<uint16_t, std::coroutine_handle<>> g_waiting_responses;

struct DnsResponseAwaiter
{
    uint16_t                   id;
    std::vector<unsigned char> response_data;

    bool await_ready() { return false; }

    void await_suspend(std::coroutine_handle<> handle)
    {
        g_waiting_responses[id] = handle;
        std::cout << "[suspend] coroutine for ID " << id << " saved to map.\n";
    }

    std::vector<unsigned char> await_resume() { return std::move(response_data); }
};

Task handle_dns_request(uint16_t client_id, std::string client_addr)
{
    // 1. 此时局部变量 client_addr 在协程栈帧(堆)中
    uint16_t remote_id = client_id + 1000; // 模拟分配一个新的外部 ID

    std::cout << "[Step 1] Sending request to Upstream for " << client_addr << "\n";

    // 2. 挂起协程，等待响应
    // 此时函数会直接返回，线程去干别的事了。
    std::vector<unsigned char> result = co_await DnsResponseAwaiter{remote_id};

    // 3. 响应回来了！此时 client_addr 依然在，逻辑直接连续执行
    std::cout << "[Step 3] Resuming! Original client was " << client_addr << ", got " << result.size() << " bytes.\n";
}

// --- 模拟网络底层 ---
void simulate_network_receive(uint16_t remote_id)
{
    if (g_waiting_responses.count(remote_id))
    {
        auto handle = g_waiting_responses[remote_id];
        g_waiting_responses.erase(remote_id);

        // 恢复协程
        handle.resume();
    }
}

int main()
{
    // 模拟两个并发请求
    auto t1 = handle_dns_request(1, "192.168.1.10");
    auto t2 = handle_dns_request(2, "10.0.0.5");

    // 此时两个协程都挂起了，handles 表里有两个 handle
    std::cout << "Main loop is free to do other things...\n";

    // 模拟外部 DNS 响应回来（乱序回来）
    simulate_network_receive(1002); // ID 2 的响应先回
    simulate_network_receive(1001); // ID 1 的响应后回

    return 0;
}