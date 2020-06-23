#include "operations.hpp"
#include "transparency.hpp"
#include <unistd/epoll.hpp>
#include <unordered_map>
#include <system_error>

namespace yurco
{
static timespec timeval2timespec(const timeval& tv)
    {
    return timespec{tv.tv_sec, tv.tv_usec * 1000};
    }

static int timespec2msec(const timespec& ts)
    {
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
    }

static timespec msec2timespec(const int msec)
    {
    return timespec{msec/1000, (msec%1000)*1000000L};
    }

static int poll2epoll_event(int poll_events)
    {
    int events = 0;
    if (poll_events & POLLIN)
        events |= EPOLLIN;
    if (poll_events & POLLOUT)
        events |= EPOLLOUT;
    if (poll_events & POLLPRI)
        events |= EPOLLPRI;
    if (poll_events & POLLRDHUP)
        events |= EPOLLRDHUP;
    if (poll_events & POLLERR)
        events |= EPOLLERR;
    if (poll_events & POLLHUP)
        events |= EPOLLHUP;
    if (poll_events & POLLRDNORM)
        events |= EPOLLRDNORM;
    if (poll_events & POLLRDBAND)
        events |= EPOLLRDBAND;
    if (poll_events & POLLWRNORM)
        events |= EPOLLWRNORM;
    if (poll_events & POLLWRBAND)
        events |= EPOLLWRBAND;
    return events;
    }

static int epoll2poll_event(int epoll_events)
    {
    int events = 0;
    if (epoll_events & EPOLLIN)
        events |= POLLIN;
    if (epoll_events & EPOLLOUT)
        events |= POLLOUT;
    if (epoll_events & EPOLLPRI)
        events |= POLLPRI;
    if (epoll_events & EPOLLRDHUP)
        events |= POLLRDHUP;
    if (epoll_events & EPOLLERR)
        events |= POLLERR;
    if (epoll_events & EPOLLHUP)
        events |= POLLHUP;
    if (epoll_events & EPOLLRDNORM)
        events |= POLLRDNORM;
    if (epoll_events & EPOLLRDBAND)
        events |= POLLRDBAND;
    if (epoll_events & EPOLLWRNORM)
        events |= POLLWRNORM;
    if (epoll_events & EPOLLWRBAND)
        events |= POLLWRBAND;
    return events;
    }

int select(const std::nothrow_t&, Reactor& reactor, Coroutine& coro, int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const struct timeval* const timeout)
    {
    if (timeout)
        {
        const struct timespec ts = timeval2timespec(*timeout);
        return pselect(std::nothrow, reactor, coro, nfds, readfds, writefds, exceptfds, &ts, nullptr);
        }
    return pselect(std::nothrow, reactor, coro, nfds, readfds, writefds, exceptfds, nullptr, nullptr);
    }

int pselect(const std::nothrow_t&, Reactor& reactor, Coroutine& coro, int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const struct timespec* const tmo_p, const sigset_t* const sigmask)
    {
    const int timeout = (tmo_p == nullptr)? -1 : timespec2msec(*tmo_p);
    std::unordered_map<int, int> fd_events_map;
    for (size_t i = 0; i < FD_SETSIZE; ++i)
        if (FD_ISSET(i, readfds))
            fd_events_map[i] |= EPOLLIN;
    for (size_t i = 0; i < FD_SETSIZE; ++i)
        if (FD_ISSET(i, writefds))
            fd_events_map[i] |= EPOLLOUT;
    for (size_t i = 0; i < FD_SETSIZE; ++i)
        if (FD_ISSET(i, exceptfds))
            fd_events_map[i] |= EPOLLERR;
    FD_ZERO(readfds);
    FD_ZERO(writefds);
    FD_ZERO(exceptfds);
    unistd::fd epfd = unistd::fd::nodup(unistd::epoll_create());
    for (const auto& fd_events : fd_events_map)
        unistd::epoll_add(epfd, fd_events.first, fd_events.second, fd_events.first);
    std::vector<epoll_event> events(fd_events_map.size());
    const int nready = epoll_pwait(std::nothrow, reactor, coro, epfd, events.data(), events.size(), timeout, sigmask);
    if (nready < 0)
        return nready;
    int result = 0;
    for (size_t i = 0; i < nready; ++i)
        {
        const auto ev = events[i].events;
        const int fd = events[i].data.fd;
        if (ev & EPOLLIN)
            {
            FD_SET(fd, readfds);
            ++result;
            }
        if (ev & EPOLLOUT)
            {
            FD_SET(fd, writefds);
            ++result;
            }
        if (ev & EPOLLERR)
            {
            FD_SET(fd, exceptfds);
            ++result;
            }
        }
    epfd.close(std::nothrow);
    return result;
    }

int poll(const std::nothrow_t&, Reactor& reactor, Coroutine& coro, struct pollfd* fds, nfds_t nfds, int timeout)
    {
    if (timeout == -1)
        return ppoll(std::nothrow, reactor, coro, fds, nfds, nullptr, nullptr);
    const struct timespec ts = msec2timespec(timeout);
    return ppoll(std::nothrow, reactor, coro, fds, nfds, &ts, nullptr);
    }

int ppoll(const std::nothrow_t&, Reactor& reactor, Coroutine& coro, struct pollfd* fds, nfds_t nfds, const struct timespec* const tmo_p, const sigset_t* const sigmask)
    {
    const int timeout = (tmo_p == nullptr)? -1 : timespec2msec(*tmo_p);
    std::unordered_map<int, pollfd*> index; // fd -> pollfd*
    index.reserve(nfds);
    unistd::fd epfd = unistd::fd::nodup(unistd::epoll_create());
    for (nfds_t i = 0; i < nfds; ++i)
        {
        const int fd = fds[i].fd;
        const int orig_events = fds[i].events;
        index[fd] = &fds[i];
        unistd::epoll_add(epfd, fd, fds[i].events, fd);
        //if (poll_events & POLLNVAL) //TODO:
        }
    std::vector<epoll_event> events(nfds);
    const int nready = epoll_pwait(std::nothrow, reactor, coro, epfd, events.data(), events.size(), timeout, sigmask);
    for (size_t i = 0; i < nready; ++i)
        {
        const auto& event = events[i];
        index[event.data.fd]->revents = epoll2poll_event(event.events);
        }
    epfd.close(std::nothrow);
    return nready;
    }

int epoll_wait(const std::nothrow_t&, Reactor& reactor, Coroutine& coro, int epfd, struct epoll_event* const events, const int maxevents, const int timeout)
    {
    return epoll_pwait(std::nothrow, reactor, coro, epfd, events, maxevents, timeout, nullptr);
    }

int epoll_pwait(const std::nothrow_t&, Reactor& reactor, Coroutine& coro, int epfd, struct epoll_event* const events, const int maxevents, const int timeout, const sigset_t* const /*sigmask*/)
    {
    for (;;)
        {
        const int nevents = ::__real_epoll_wait(epfd, events, maxevents, 0); // timeout=0 equal NONBLOCK
        if (0 == nevents)
            {
            reactor.suspend(coro, epfd, EPOLLIN); // TODO: timeout
            continue;
            }
        return nevents;
        }
    }

int close(const std::nothrow_t&, Reactor& reactor, const int fd) noexcept
    {
    return reactor.close(std::nothrow, fd);
    }

size_t read(const std::nothrow_t&, Reactor& reactor, Coroutine& coro, const int fd, void* const buf, const size_t count)
    {
    for (;;)
        {
        const ssize_t nread = ::__real_read(fd, buf, count);
        if (-1 == nread && errno == EAGAIN)
            {
            reactor.suspend(coro, fd, EPOLLIN);
            continue;
            }
        return nread;
        }
    }

size_t write(const std::nothrow_t&, Reactor& reactor, Coroutine& coro, const int fd, const void* const buf, const size_t count)
    {
    for (;;)
        {
        const ssize_t nwrite = ::__real_write(fd, buf, count);
        if (-1 == nwrite && errno == EAGAIN)
            {
            reactor.suspend(coro, fd, EPOLLOUT);
            continue;
            }
        return nwrite;
        }
     }

int connect(const std::nothrow_t&, Reactor& reactor, Coroutine& coro, const int fd, const struct sockaddr* const addr, const socklen_t addrlen)
    {
    for (;;)
        {
        int flags = fcntl(fd, F_GETFL);
        flags |= O_NONBLOCK;
        fcntl(fd, F_SETFL, flags);
        const int ret = ::__real_connect(fd, addr, addrlen);
        if (-1 == ret && (errno == EAGAIN || errno == EINPROGRESS))
            {
            reactor.suspend(coro, fd, EPOLLOUT);
            int err = 0;
            socklen_t err_len = sizeof(err);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &err_len) < 0)
                return errno;
            if (err)
                {
                errno = err;
                return -1;
                }
            return 0;
            }
        return ret;
        }
    }

int accept(const std::nothrow_t&, Reactor& reactor, Coroutine& coro, const int fd, ::sockaddr* addr, socklen_t* addrlen)
    {
    return accept4(std::nothrow, reactor, coro, fd, addr, addrlen, 0);
    }

int accept4(const std::nothrow_t&, Reactor& reactor, Coroutine& coro, const int fd, ::sockaddr* addr, socklen_t* addrlen, const int flags)
    {
    for (;;)
        {
        const int ret = ::__real_accept4(fd, addr, addrlen, flags);
        if (-1 == ret && errno == EAGAIN)
            {
            reactor.suspend(coro, fd, EPOLLIN);
            continue;
            }
        return ret;
        }
    }


ssize_t recv(const std::nothrow_t&, Reactor& reactor, Coroutine& coro, const int fd, void* const buf, const size_t len, const int flags)
    {
    for (;;)
        {
        const int ret = ::__real_recv(fd, buf, len, flags | O_NONBLOCK);
        if (-1 == ret && errno == EAGAIN)
            {
            reactor.suspend(coro, fd, EPOLLIN);
            continue;
            }
        return ret;
        }
    }

ssize_t recvfrom(const std::nothrow_t&, Reactor& reactor, Coroutine& coro, const int fd, void* const buf, const size_t len, const int flags, struct sockaddr* const src_addr, socklen_t* const addrlen)
    {
    for (;;)
        {
        const int ret = ::__real_recvfrom(fd, buf, len, flags | O_NONBLOCK, src_addr, addrlen);
        if (-1 == ret && errno == EAGAIN)
            {
            reactor.suspend(coro, fd, EPOLLIN);
            continue;
            }
        return ret;
        }
    }

ssize_t recvmsg(const std::nothrow_t&, Reactor& reactor, Coroutine& coro, const int fd, struct msghdr* const msg, const int flags)
    {
    for (;;)
        {
        const int ret = ::__real_recvmsg(fd, msg, flags | O_NONBLOCK);
        if (-1 == ret && errno == EAGAIN)
            {
            reactor.suspend(coro, fd, EPOLLIN);
            continue;
            }
        return ret;
        }
    }

ssize_t send(const std::nothrow_t&, Reactor& reactor, Coroutine& coro, int fd, const void* msg, size_t len, int flags)
    {
    for (;;)
        {
        const int ret = ::__real_send(fd, msg, len, flags | O_NONBLOCK);
        if (-1 == ret && errno == EAGAIN)
            {
            reactor.suspend(coro, fd, EPOLLOUT);
            continue;
            }
        return ret;
        }
    }

ssize_t sendto(const std::nothrow_t&, Reactor& reactor, Coroutine& coro, int fd, const void* msg, size_t len, int flags, const struct sockaddr* to, socklen_t tolen)
    {
    for (;;)
        {
        const int ret = ::__real_sendto(fd, msg, len, flags | O_NONBLOCK, to, tolen);
        if (-1 == ret && errno == EAGAIN)
            {
            reactor.suspend(coro, fd, EPOLLOUT);
            continue;
            }
        return ret;
        }
    }

ssize_t sendmsg(const std::nothrow_t&, Reactor& reactor, Coroutine& coro, int fd, const struct msghdr* msg, int flags)
    {
    for (;;)
        {
        const int ret = ::__real_sendmsg(fd, msg, flags | O_NONBLOCK);
        if (-1 == ret && errno == EAGAIN)
            {
            reactor.suspend(coro, fd, EPOLLOUT);
            continue;
            }
        return ret;
        }
    }

int select(Reactor& reactor, Coroutine& coro, int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const struct timeval* const timeout)
    {
    const int nready = select(std::nothrow, reactor, coro, nfds, readfds, writefds, exceptfds, timeout);
    if (-1 == nready)
        throw std::system_error(errno, std::system_category(), "select");
    return nready;
    }

int pselect(Reactor& reactor, Coroutine& coro, int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const struct timespec* const timeout, const sigset_t* const sigmask)
    {
    const int nready = pselect(std::nothrow, reactor, coro, nfds, readfds, writefds, exceptfds, timeout, sigmask);
    if (-1 == nready)
        throw std::system_error(errno, std::system_category(), "pselect");
    return nready;
    }

int poll(Reactor& reactor, Coroutine& coro, struct pollfd* fds, nfds_t nfds, int timeout)
    {
    const int nready = poll(std::nothrow, reactor, coro, fds, nfds, timeout);
    if (-1 == nready)
        throw std::system_error(errno, std::system_category(), "poll");
    return nready;
    }

int ppoll(Reactor& reactor, Coroutine& coro, struct pollfd* fds, nfds_t nfds, const struct timespec* const tmo_p, const sigset_t* const sigmask)
    {
    const int nready = ppoll(std::nothrow, reactor, coro, fds, nfds, tmo_p, sigmask);
    if (-1 == nready)
        throw std::system_error(errno, std::system_category(), "ppoll");
    return nready;
    }

int epoll_wait(Reactor& reactor, Coroutine& coro, int epfd, struct epoll_event* const events, const int maxevents, const int timeout)
    {
    const int nevents = epoll_wait(std::nothrow, reactor, coro, epfd, events, maxevents, timeout);
    if (-1 == nevents)
        throw std::system_error(errno, std::system_category(), "epoll_wait");
    return nevents;
    }

int epoll_pwait(Reactor& reactor, Coroutine& coro, int epfd, struct epoll_event* const events, const int maxevents, const int timeout, const sigset_t* const sigmask)
    {
    const int nevents = epoll_pwait(std::nothrow, reactor, coro, epfd, events, maxevents, timeout, sigmask);
    if (-1 == nevents)
        throw std::system_error(errno, std::system_category(), "epoll_pwait");
    return nevents;
    }

void close(Reactor& reactor, const int fd)
    {
    reactor.close(fd);
    }

size_t read(Reactor& reactor, Coroutine& coro, const int fd, void* const buf, const size_t count)
    {
    const size_t nread = read(std::nothrow, reactor, coro, fd, buf, count);
    if (-1 == nread)
        throw std::system_error(errno, std::system_category(), "read");
    return nread;
    }

size_t write(Reactor& reactor, Coroutine& coro, const int fd, const void* const buf, const size_t count)
    {
    const size_t nwrite = write(std::nothrow, reactor, coro, fd, buf, count);
    if (-1 == nwrite)
        throw std::system_error(errno, std::system_category(), "write");
    return nwrite;
    }

void connect(Reactor& reactor, Coroutine& coro, const int fd, const struct sockaddr* const addr, const socklen_t addrlen)
    {
    const int ret = connect(std::nothrow, reactor, coro, fd, addr, addrlen);
    if (-1 == ret)
        throw std::system_error(errno, std::system_category(), "connect");
    }

int accept(Reactor& reactor, Coroutine& coro, const int fd, ::sockaddr* addr, socklen_t* addrlen)
    {
    const int client = accept(std::nothrow, reactor, coro, fd, addr, addrlen);
    if (-1 == client)
        throw std::system_error(errno, std::system_category(), "accept");
    return client;
    }

int accept4(Reactor& reactor, Coroutine& coro, const int fd, ::sockaddr* addr, socklen_t* addrlen, const int flags)
    {
    const int client = accept4(std::nothrow, reactor, coro, fd, addr, addrlen, flags);
    if (-1 == client)
        throw std::system_error(errno, std::system_category(), "accept4");
    return client;
    }

ssize_t recv(Reactor& reactor, Coroutine& coro, const int fd, void* const buf, const size_t len, const int flags)
    {
    const ssize_t ret = recv(reactor, coro, fd, buf, len, flags);
    if (-1 == ret)
        throw std::system_error(errno, std::system_category(), "recv");
    return ret;
    }

ssize_t recvfrom(Reactor& reactor, Coroutine& coro, const int fd, void* const buf, const size_t len, const int flags, struct sockaddr* const src_addr, socklen_t* const addrlen)
    {
    const ssize_t ret = recvfrom(reactor, coro, fd, buf, len, flags, src_addr, addrlen);
    if (-1 == ret)
        throw std::system_error(errno, std::system_category(), "recvfrom");
    return ret;
    }

ssize_t recvmsg(Reactor& reactor, Coroutine& coro, const int fd, struct msghdr* const msg, const int flags)
    {
    const ssize_t ret = recvmsg(reactor, coro, fd, msg, flags);
    if (-1 == ret)
        throw std::system_error(errno, std::system_category(), "recvmsg");
    return ret;
    }

ssize_t send(Reactor& reactor, Coroutine& coro, int fd, const void* msg, size_t len, int flags)
    {
    const ssize_t ret = send(reactor, coro, fd, msg, len, flags);
    if (-1 == ret)
        throw std::system_error(errno, std::system_category(), "send");
    return ret;
    }

ssize_t sendto(Reactor& reactor, Coroutine& coro, int fd, const void* msg, size_t len, int flags, const struct sockaddr* to, socklen_t tolen)
    {
    const ssize_t ret = sendto(reactor, coro, fd, msg, len, flags, to, tolen);
    if (-1 == ret)
        throw std::system_error(errno, std::system_category(), "sendto");
    return ret;
    }

ssize_t sendmsg(Reactor& reactor, Coroutine& coro, int fd, const struct msghdr* msg, int flags)
    {
    const ssize_t ret = sendmsg(reactor, coro, fd, msg, flags);
    if (-1 == ret)
        throw std::system_error(errno, std::system_category(), "sendmsg");
    return ret;
    }

} // namespace yurco

