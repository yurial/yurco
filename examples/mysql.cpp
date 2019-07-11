#include <yurco/all.hpp>
#include <unistd/time.hpp>
#include <unistd/signalfd.hpp>
#include <unistd/addrinfo.hpp>
#include <unistd/netdb.hpp>

#include <mysql/mysql.h>

#include <iostream>
#include <thread>
#include <mutex>
#include <signal.h>
#include <stdlib.h>

std::mutex mutex; // mutex to synchronize std::cerr output

void process_connection(unistd::fd& fd)
    {
    try
        {
        /* Create a connection */
        std::unique_ptr<MYSQL, std::function<decltype(mysql_close)>> con(mysql_init(nullptr), mysql_close);
        mysql_real_connect(con.get(), "db.local", "ro", "", nullptr, 0, nullptr, 0);
        mysql_query(con.get(), "SELECT NOW(), SLEEP(10);");
        std::unique_ptr<MYSQL_RES, std::function<decltype(mysql_free_result)>> result(mysql_store_result(con.get()), mysql_free_result);
        if (!result)
            return; // silently close connection
        for (MYSQL_ROW row = mysql_fetch_row(result.get()); row; row = mysql_fetch_row(result.get()))
            {
            static char header[] = "HTTP/1.1 200 OK\r\nContent-Length: 21\r\nConnection: close\r\n\r\n";
            unistd::write_all(fd, header, strlen(header));
            const char* const answer = row[0];
            unistd::write_all(fd, answer, strlen(answer));
            unistd::write_all(fd, "\r\n", 2);
            }
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

void listener(unistd::fd& sock)
    {
    try
        {
        for (;;)
            {
            for (size_t i = 0; i < 32; ++i) // sometimes we should yield() to processing accepted connections
                {
                unistd::fd clientfd = unistd::fd::nodup(unistd::accept4(sock, nullptr, nullptr, SOCK_NONBLOCK));
                yurco::async(process_connection, std::move(clientfd));
                }
            yurco::yield();
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

void signal_handler(unistd::fd& sigfd)
    {
    yurco::suspend(sigfd, EPOLLIN);
    std::cerr << "we got a signal" << std::endl;
    // use unistd::read(sigfd) to get a signals instead of yurco::suspend
    yurco::terminate();
    }

void balast_handler()
    {
    uint64_t counter = 0;
    for (;;)
        {
        ++counter;
        yurco::yield();
        }
    }

void register_signal_handler()
    {
    sigset_t sigmask;
    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGINT);
    sigaddset(&sigmask, SIGTERM);
    sigaddset(&sigmask, SIGQUIT);
    unistd::fd sigfd = unistd::fd::nodup(unistd::signalfd(sigmask));
    yurco::async(signal_handler, std::move(sigfd)); // use std::move to avoid ::dup() file descriptior
    sigaddset(&sigmask, SIGPIPE); // SIGPIPE just ignored and not processed
    sigprocmask(SIG_BLOCK, &sigmask, nullptr);
    }

void register_listener()
    {
    const std::vector<unistd::addrinfo> addr = unistd::getaddrinfo("localhost:31337"); // or [::]:31337 or other valid variants
    unistd::fd sock = unistd::fd::nodup(unistd::socket(addr.at(0), SOCK_NONBLOCK));
    unistd::setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, 1);
    unistd::setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, 3);
    unistd::setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, 1);
    unistd::setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, 1);
    unistd::setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, 1); // keep-alive not required, but good practic
    unistd::bind(sock, addr.at(0));
    unistd::listen(sock, 8192/*backlog*/);
    yurco::async(listener, std::move(sock)); // use std::move to avoid ::dup() file descriptior
    }

void async_main()
    {
    register_signal_handler();
    register_listener();
    }

int main()
    {
    const size_t stack_size = 16*1024; // size less than 16k lead to SIGSEGV cause libunwind require more space
    yurco::init(stack_size);
    yurco::async(async_main);
    #ifdef SINGLE_THREAD
    yurco::run();
    #else
    const size_t threads_count = std::thread::hardware_concurrency() / 2; // or any other value, if doubt
    std::vector<std::thread> threads;
    for (size_t i = 0; i < threads_count; ++i)
        threads.emplace_back(std::thread([]() { yurco::run(); }));
    for (std::thread& t : threads)
        t.join();
    #endif
    return EXIT_SUCCESS;
    }
