#include "operations.hpp"

namespace yurco
{

fd::fd(yurco::Reactor& r) noexcept:
        unistd::fd(),
        m_reactor(r)
    {
    }

fd::fd(fd&& origin) noexcept:
        unistd::fd(),
        m_reactor(origin.m_reactor)
    {
    std::swap(m_fd, origin.m_fd);
    }

fd::fd(const fd& origin):
        unistd::fd(),
        m_reactor(origin.m_reactor)
    {
    if (fd::bad_fileno != origin)
        m_fd = unistd::dup(origin.m_fd);
    }

fd::~fd() noexcept
    {
    close();
    }

yurco::Reactor& fd::reactor()
    {
    return m_reactor;
    }

void fd::close()
    {
    if (fd::bad_fileno == m_fd)
        return;
    const int fd_val = m_fd;
    m_fd = fd::bad_fileno;
    yurco::close(reactor(), fd_val);
    }

int fd::close(const std::nothrow_t&) noexcept
    {
    if (fd::bad_fileno == m_fd)
        return 0;
    const int fd_val = m_fd;
    m_fd = fd::bad_fileno;
    return yurco::close(std::nothrow, reactor(), fd_val);
    }

fd fd::accept(yurco::Coroutine& coro, int flags)
    {
    return accept(coro, nullptr, 0, flags);
    }

fd fd::accept(yurco::Coroutine& coro, ::sockaddr* addr, socklen_t* addrlen, int flags)
    {
    return fd::nodup(reactor(), yurco::accept(reactor(), coro, *this, addr, addrlen, flags));
    }

size_t fd::read(yurco::Coroutine& coro, void* buf, size_t count)
    {
    return yurco::read(reactor(), coro, *this, buf, count);
    }

size_t fd::write(yurco::Coroutine& coro, const void* buf, size_t count)
    {
    return yurco::write(reactor(), coro, *this, buf, count);
    }

fd fd::dup(yurco::Reactor& r, native_type val)
    {
    fd result(r);
    if (fd::bad_fileno != val)
        result.m_fd = unistd::dup(val);
    return result;
    }

fd fd::nodup(yurco::Reactor& r, native_type val) noexcept
    {
    fd result(r);
    result.m_fd = val;
    return result;
    }

} // namespace yurco

