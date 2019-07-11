#pragma once

#include "reactor.hpp"

#include <new>

namespace yurco
{

int     close(const std::nothrow_t&, Reactor& reactor, const int fd) noexcept __attribute__((warn_unused_result));
size_t  read(const std::nothrow_t&, Reactor& reactor, Coroutine& coro, const int fd, void* const buf, const size_t count) __attribute__((warn_unused_result));
size_t  write(const std::nothrow_t&, Reactor& reactor, Coroutine& coro, const int fd, const void* const buf, const size_t count) __attribute__((warn_unused_result));

int     connect(const std::nothrow_t&, Reactor& reactor, Coroutine& coro, const int fd, const struct sockaddr* const addr, const socklen_t addrlen);
int     accept(const std::nothrow_t&, Reactor& reactor, Coroutine& coro, const int fd, ::sockaddr* addr, socklen_t* addrlen, const int flags = 0) __attribute__((warn_unused_result));
ssize_t recv(const std::nothrow_t&, Reactor& reactor, Coroutine& coro, const int fd, void* const buf, const size_t len, const int flags);
ssize_t recvfrom(const std::nothrow_t&, Reactor& reactor, Coroutine& coro, const int fd, void* const buf, const size_t len, const int flags, struct sockaddr* const src_addr, socklen_t* const addrlen) __attribute__((warn_unused_result));
ssize_t recvmsg(const std::nothrow_t&, Reactor& reactor, Coroutine& coro, const int fd, struct msghdr* const msg, const int flags) __attribute__((warn_unused_result));
ssize_t send(const std::nothrow_t&, Reactor& reactor, Coroutine& coro, int fd, const void* msg, size_t len, int flags) __attribute__((warn_unused_result));
ssize_t sendto(const std::nothrow_t&, Reactor& reactor, Coroutine& coro, int fd, const void* msg, size_t len, int flags, const struct sockaddr* to, socklen_t tolen) __attribute__((warn_unused_result));
ssize_t sendmsg(const std::nothrow_t&, Reactor& reactor, Coroutine& coro, int fd, const struct msghdr* msg, int flags) __attribute__((warn_unused_result));

void    close(Reactor& reactor, const int fd);
size_t  read(Reactor& reactor, Coroutine& coro, const int fd, void* const buf, const size_t count) __attribute__((warn_unused_result));
size_t  write(Reactor& reactor, Coroutine& coro, const int fd, const void* const buf, const size_t count) __attribute__((warn_unused_result));

void    connect(Reactor& reactor, Coroutine& coro, const int fd, const struct sockaddr* const addr, const socklen_t addrlen);
int     accept(Reactor& reactor, Coroutine& coro, const int fd, ::sockaddr* addr, socklen_t* addrlen, const int flags = 0) __attribute__((warn_unused_result));
ssize_t recv(Reactor& reactor, Coroutine& coro, const int fd, void* const buf, const size_t len, const int flags);
ssize_t recvfrom(Reactor& reactor, Coroutine& coro, const int fd, void* const buf, const size_t len, const int flags, struct sockaddr* const src_addr, socklen_t* const addrlen) __attribute__((warn_unused_result));
ssize_t recvmsg(Reactor& reactor, Coroutine& coro, const int fd, struct msghdr* const msg, const int flags) __attribute__((warn_unused_result));
ssize_t send(Reactor& reactor, Coroutine& coro, int fd, const void* msg, size_t len, int flags) __attribute__((warn_unused_result));
ssize_t sendto(Reactor& reactor, Coroutine& coro, int fd, const void* msg, size_t len, int flags, const struct sockaddr* to, socklen_t tolen) __attribute__((warn_unused_result));
ssize_t sendmsg(Reactor& reactor, Coroutine& coro, int fd, const struct msghdr* msg, int flags) __attribute__((warn_unused_result));

} // namespace yurco

