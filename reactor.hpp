#pragma once

#include "coroutine.hpp"
#include "scheduler.hpp"
#include "lock.hpp"
#include <unistd/fd.hpp>
#include <unistd/epoll.hpp>
#include <list>
#include <atomic>
#include <unordered_map>
#include <netinet/in.h>

namespace yurco
{

class Reactor
{
public:
                Reactor(const size_t stack_size, const bool protect_stack=true) noexcept;
                Reactor(const Reactor&) = delete;

template <class Func, class... Args>
inline  void    coroutine(Func&& func, Args&&... args) noexcept;
template <class Func, class... Args>
inline  void    async(Func&& func, Args&&... args) noexcept;
        void    run(const size_t batch_size=16, const size_t events_at_once=1024) noexcept;
        void    terminate() noexcept;
        void    suspend(Coroutine& coro, const int fd, int events);
        void    close(const int fd);
        int     close(const std::nothrow_t&, const int fd) noexcept;

protected:
enum class epoll_action
    {
    none,
    add,
    modify
    }; // enum epoll_action
struct fd_data
    {
    Coroutine*  coro = nullptr;
    int         events = 0;
    inline fd_data() = default;
    inline fd_data(Coroutine* c, int e) noexcept: coro(c), events(e) {}
    };
using fds_container = std::unordered_map<int, fd_data>;
std::atomic<bool>   m_terminate;
lock_type           m_fd_mutex;
lock_type           m_epoll_mutex;
fds_container       m_fds;
unistd::fd          m_epoll_wakeup;
unistd::fd          m_epollfd;
SimpleScheduler     m_scheduler;

inline  void    nothing_to_do() noexcept;
inline  bool    process_ready(const size_t batch_size) noexcept;
inline  bool    process_epoll(std::vector<epoll_event>& events, std::vector<Coroutine*>& ready, const bool has_ready) noexcept;
        void    update_epoll(Coroutine& coro, const int fd, int events) noexcept;
epoll_action    update_fds(Coroutine& coro, const int fd, int events) noexcept;
}; // class Reactor

template <class Func, class... Args>
void Reactor::coroutine(Func&& func, Args&&... args) noexcept
    {
    m_scheduler.coroutine(std::forward<Func>(func), std::forward<Args>(args)...);
    }

template <class Func, class... Args>
void Reactor::async(Func&& func, Args&&... args) noexcept
    {
    coroutine(std::forward<Func>(func), std::forward<Args>(args)...);
    }

} // namespace yurco

