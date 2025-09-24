#include <iostream>

namespace ab {
    int add(int, int);
    template <class T>
T sub (T value1, T value2){
     T sum = value1-value2;
    return sum;
}
}

int
main
()
{
    ab::add(1,2);
    std::cout<<"1" << ab::add(1,2) << ab::sub(5.3,3.1) << ab::sub(4,3);
return 0;
}
