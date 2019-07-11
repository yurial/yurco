#include "all.hpp"
#include "guards.hpp"
#include <unistd/eventfd.hpp>
#include <sys/types.h>
#include <sys/socket.h>

#ifndef YURCO_IDLE_TIMEOUT_USEC
#define YURCO_IDLE_TIMEOUT_USEC 1000
#endif

namespace yurco
{

size_t epoll_wait_retry(int epollfd, std::vector<epoll_event>& events, int timeout) noexcept
    {
    for (;;)
        {
        try
            {
            return unistd::epoll_wait(epollfd, events.data(), events.size(), timeout);
            }
        catch (const std::system_error& e)
            {
            if (e.code().value() == EINTR)
                return 0;
            throw;
            }
        }
    }

Reactor::Reactor(const size_t stack_size, const bool protect_stack) noexcept:
        m_epoll_wakeup(unistd::fd::nodup(unistd::eventfd(0, EFD_NONBLOCK))),
        m_epollfd(unistd::fd::nodup(unistd::epoll_create())),
        m_scheduler(stack_size, protect_stack)
    {
    const int events = EPOLLIN;
    m_fds.emplace(std::piecewise_construct,
         std::forward_as_tuple(m_epoll_wakeup),
         std::forward_as_tuple(nullptr, events)
         );
    unistd::epoll_add(m_epollfd, m_epoll_wakeup, events, m_epoll_wakeup);
    }

void Reactor::run(const size_t batch_size, const size_t events_at_once) noexcept
    {
    std::vector<epoll_event> events(events_at_once);
    std::vector<Coroutine*> ready;
    ready.reserve(events_at_once);
    m_terminate = false;
    eventfd_t wakeup_value = 0;
    ::eventfd_read(m_epoll_wakeup, &wakeup_value);
    yurco::set_reactor(*this);
    for (;;)
        {
        bool has_ready = process_ready(batch_size);
        if (m_terminate && m_scheduler.has_suspended())
            {
            m_scheduler.terminate();
            has_ready = m_scheduler.has_ready();
            }
        else if (m_terminate && !has_ready)
            return;
        else if (m_terminate)
            continue;
        else if (process_epoll(events, ready, has_ready))
            continue;
        nothing_to_do();
        }
    }

void Reactor::nothing_to_do() noexcept
    {
    #ifdef SINGLE_THREAD
    abort();
    #else
    usleep(YURCO_IDLE_TIMEOUT_USEC);
    #endif
    }

bool Reactor::process_ready(const size_t batch_size) noexcept
    {
    for (size_t i = 0; i < batch_size; ++i)
        if (!m_scheduler.try_execute_one())
            return false;
    return true;
    }

bool Reactor::process_epoll(std::vector<epoll_event>& events, std::vector<Coroutine*>& ready, const bool has_ready) noexcept
    {
    if (!m_epoll_mutex.try_lock())
        return false;
    #ifdef SINGLE_THREAD
    const int timeout = has_ready? 0 : -1;
    #else
    const int timeout = has_ready? 0 : (YURCO_IDLE_TIMEOUT_USEC/1000);
    #endif
    // wait events
    const size_t nevents = epoll_wait_retry(m_epollfd, events, timeout);
    m_epoll_mutex.unlock();
    if (m_terminate)
        return true;
    if (nevents == 0)
        return true;
    // mark coros as ready
        {
        const lock_guard lock(m_fd_mutex);
        for (size_t i = 0; i < nevents; ++i)
            {
            const auto& event = events[i];
            const fd_data& data = m_fds[event.data.fd];
            if (!data.coro) // coro yield without awaiting events, just skip
                continue;
            ready.push_back(data.coro);
            }
        }
    m_scheduler.resume_many(ready);
    ready.resize(0);
    return true;
    }

void Reactor::terminate() noexcept
    {
    m_terminate = true;
    m_scheduler.terminate();
    unistd::eventfd_write(m_epoll_wakeup, 1);
    }

Reactor::epoll_action Reactor::update_fds(Coroutine& coro, unistd::fd::native_type fd, int events) noexcept
    {
    const lock_guard lock(m_fd_mutex);
    auto result = m_fds.emplace(std::piecewise_construct,
                         std::forward_as_tuple(fd),
                         std::forward_as_tuple(&coro, events)
                         );
    const auto fds_it = result.first;
    if (result.second)
        return epoll_action::add;
    fds_it->second.coro = &coro;
    if (fds_it->second.events == events)
        return epoll_action::none;
    fds_it->second.events = events;
    return epoll_action::modify;
    }

void Reactor::update_epoll(Coroutine& coro, const int fd, int events) noexcept
    {
    events |= EPOLLET | EPOLLERR | EPOLLHUP;
    const epoll_action action = update_fds(coro, fd, events);
    switch (action)
        {
        case epoll_action::add:
            unistd::epoll_add(m_epollfd, fd, events, fd);
            break;
        case epoll_action::modify:
            unistd::epoll_mod(m_epollfd, fd, events, fd);
            break;
        case epoll_action::none:
            break;
        }
    }

void Reactor::close(const int fd)
    {
    const int ret = close(std::nothrow, fd);
    if (0 != ret)
        throw std::system_error(errno, std::system_category(), "close()");
    }

int Reactor::close(const std::nothrow_t&, const int fd) noexcept
    {
    // no need to call ::epoll_ctl(m_epollfd, EPOLL_CTL_DEL, fd, nullptr); //silently delete fd from epoll
        {
        const lock_guard lock(m_fd_mutex);
        m_fds.erase(fd);
        }
    return ::__real_close(fd);
    }

void Reactor::suspend(Coroutine& coro, const int fd, int events)
    {
    m_scheduler.suspend(coro);
    update_epoll(coro, fd, events);
    coro.yield();
    }

} // namespace yurco

