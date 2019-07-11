#include <yurco/all.hpp>
#include <iostream>

void single(yurco::Reactor& reactor, int x)
    {
    std::cerr << x << std::endl;
    reactor.terminate();
    }

int main()
    {
    yurco::Reactor reactor(16*1024);
    reactor.coroutine(single, std::ref(reactor), 666);
    reactor.run();
    return EXIT_SUCCESS;
    }
