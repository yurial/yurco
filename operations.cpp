#include "operations.hpp"
#include "transparency.hpp"
#include <unistd/epoll.hpp>
#include <system_error>

namespace yurco
{

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

int accept(const std::nothrow_t&, Reactor& reactor, Coroutine& coro, const int fd, ::sockaddr* addr, socklen_t* addrlen, const int flags)
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

int accept(Reactor& reactor, Coroutine& coro, const int fd, ::sockaddr* addr, socklen_t* addrlen, const int flags)
    {
    const int client = accept(std::nothrow, reactor, coro, fd, addr, addrlen, flags);
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

