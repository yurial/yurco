#include <yurco/all.hpp>
#include <unistd/time.hpp>
#include <unistd/signalfd.hpp>
#include <unistd/addrinfo.hpp>
#include <unistd/netdb.hpp>
#include <iostream>
#include <thread>
#include <signal.h>
#include <stdlib.h>

std::mutex mutex; // mutex to synchronize std::cerr output

void process_connection(yurco::Coroutine& coro, yurco::fd& fd)
    {
    (void)coro;
    (void)fd;
    char buf[1024];
    try
        {
        const size_t nread = fd.read(coro, buf, sizeof(buf));
        if (0 != nread)
            {
            static char answer[] = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nOk\r\n";
            try
                {
                for (size_t nwrite = 0; nwrite < sizeof(answer);)
                    nwrite += fd.write(coro, answer+nwrite, sizeof(answer)-nwrite);
                }
            catch (const yurco::terminate_exception&)
                {
                const std::lock_guard<std::mutex> lock(mutex);
                std::cerr << "terminate connection coroutine while write" << std::endl;
                }
            catch (...)
                {
                const std::lock_guard<std::mutex> lock(mutex);
                std::cerr << "unknown exception while write" << std::endl;
                }
            }
        }
    catch (const yurco::terminate_exception&)
        {
        const std::lock_guard<std::mutex> lock(mutex);
        std::cerr << "terminate connection coroutine while read" << std::endl;
        }
    catch (...)
        {
        const std::lock_guard<std::mutex> lock(mutex);
        std::cerr << "unknown exception while read" << std::endl;
        }
    fd.close();
    }

void listener(yurco::Coroutine& coro, yurco::fd& sock)
    {
    try
        {
        for (;;)
            {
            for (size_t i = 0; i < 32; ++i) // sometimes we should yield() to processing accepted connections
                {
                yurco::fd clientfd = sock.accept(coro, SOCK_NONBLOCK);
                sock.reactor().coroutine(process_connection, std::move(clientfd));
                }
            coro.yield();
            }
        }
    catch (const yurco::terminate_exception&)
        {
        const std::lock_guard<std::mutex> lock(mutex);
        std::cerr << "terminate listener coroutine" << std::endl;
        }
    catch (...)
        {
        const std::lock_guard<std::mutex> lock(mutex);
        std::cerr << "unknwon exception while accept" << std::endl;
        }
    }

void signal_handler(yurco::Coroutine& coro, yurco::fd& sigfd)
    {
    sigfd.reactor().suspend(coro, sigfd, EPOLLIN);
    std::cerr << "we got a signal" << std::endl;
    // use unistd::read(sigfd) to get a signals
    sigfd.reactor().terminate();
    sigfd.close();
    }

void balast_handler(yurco::Coroutine& coro)
    {
    uint64_t counter = 0;
    for (;;)
        {
        ++counter;
        coro.yield();
        }
    }

void register_signal_handler(yurco::Reactor& reactor)
    {
    sigset_t sigmask;
    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGINT);
    sigaddset(&sigmask, SIGTERM);
    sigaddset(&sigmask, SIGQUIT);
    yurco::fd sigfd = yurco::fd::nodup(reactor, unistd::signalfd(sigmask));
    reactor.coroutine(signal_handler, std::move(sigfd)); // use std::move to avoid ::dup() file descriptior
    sigaddset(&sigmask, SIGPIPE); // SIGPIPE just ignored and not processed
    sigprocmask(SIG_BLOCK, &sigmask, nullptr);
    }

void register_listener(yurco::Reactor& reactor)
    {
    const std::vector<unistd::addrinfo> addr = unistd::getaddrinfo("localhost:31337"); // or [::]:31337 or other valid variants
    yurco::fd sock = yurco::fd::nodup(reactor, unistd::socket(addr.at(0), SOCK_NONBLOCK));
    unistd::setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, 1);
    unistd::setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, 3);
    unistd::setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, 1);
    unistd::setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, 1);
    unistd::setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, 1); // keep-alive not required, but good practic
    unistd::bind(sock, addr.at(0));
    unistd::listen(sock, 8192/*backlog*/);
    reactor.coroutine(listener, std::move(sock)); // use std::move to avoid ::dup() file descriptior
    }

#ifdef SINGLE_THREAD
void singlethread_main()
    {
    const size_t stack_size = 16*1024; // size less than 16k lead to SIGSEGV cause libunwind require more space
    yurco::Reactor reactor(stack_size);
    register_listener(reactor);
    register_signal_handler(reactor);
    //for (size_t i = 0; i < threads_count; ++i)
    //    reactor.coroutine(balast_handler);
    reactor.run();
    }

#else

void multithread_main()
    {
    const size_t threads_count = std::thread::hardware_concurrency(); // or any other value, if doubt
    //const size_t threads_count = 1;
    const size_t stack_size = 16*1024; // size less than 16k lead to SIGSEGV cause libunwind require more space
    yurco::Reactor reactor(stack_size);
    register_listener(reactor);
    register_signal_handler(reactor);
    //for (size_t i = 0; i < threads_count; ++i)
    //    reactor.coroutine(balast_handler);
    auto entry = [&reactor] () -> void {reactor.run();};
    std::vector<std::thread> threads;
    for (size_t i = 0; i < threads_count; ++i)
        threads.emplace_back(std::thread(entry));
    for (std::thread& t : threads)
        t.join();
    }
#endif

int main()
    {
    #ifdef SINGLE_THREAD
    singlethread_main();
    #else
    multithread_main();
    #endif
    return EXIT_SUCCESS;
    }
