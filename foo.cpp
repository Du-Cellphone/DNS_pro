#include <iostream>
#include <utility>
#include <vector>


void process(int &x)
{
    std::cout << "Left value\n";
}
void process(int &&x)
{
    std::cout << "Right value\n";
}

template <typename T>
void f(std::vector<T> &&x)
{
}

template <typename... Args>
void g(Args &&...args)
{
}

template <typename T>
void wrapper(T &&arg)
{ // arg 是一个万能引用

    process(std::forward<T>(arg)); // 无论你传入什么，arg 到了这里都有名字，它是一个左值！
}

int main()
{
    int a = 10;
    wrapper(a);  // 传入左值 -> process(int&)
    wrapper(10); // 传入右值 -> 依然调用 process(int&)，因为 arg 本身是左值！
    std::vector<int> b;
    f(std::move(b));
    int &&c = 10;
    std::cout << c << '\n';
}