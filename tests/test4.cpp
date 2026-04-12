#include <vector>
#include <iostream>

int main()
{
    std::vector<int> v;
    v.resize(10);

    for (int i = 0; i < 10; ++i)
        v[i] = i;
    for (int x : v)
        std::cout << x << " ";
    std::cout << std::endl;
    return 0;
}