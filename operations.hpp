#pragma once

#include "reactor.hpp"

#include <new>
#include <poll.h>

namespace yurco
{
int     select(const std::nothrow_t&, Reactor& reactor, Coroutine& coro, int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const struct timeval* const timeout);
int     pselect(const std::nothrow_t&, Reactor& reactor, Coroutine& coro, int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const struct timespec* const timeout, const sigset_t* const sigmask);
int     poll(const std::nothrow_t&, Reactor& reactor, Coroutine& coro, struct pollfd* fds, nfds_t nfds, int timeout);
int     ppoll(const std::nothrow_t&, Reactor& reactor, Coroutine& coro, struct pollfd* fds, nfds_t nfds, const struct timespec* const tmo_p, const sigset_t* const sigmask);
int     epoll_wait(const std::nothrow_t&, Reactor& reactor, Coroutine& coro, int epfd, struct epoll_event* const events, const int maxevents, const int timeout);
int     epoll_pwait(const std::nothrow_t&, Reactor& reactor, Coroutine& coro, int epfd, struct epoll_event* const events, const int maxevents, const int timeout, const sigset_t* const sigmask);

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

int     select(Reactor& reactor, Coroutine& coro, int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const struct timeval* const timeout);
int     pselect(Reactor& reactor, Coroutine& coro, int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const struct timespec* const timeout, const sigset_t* const sigmask);
int     poll(Reactor& reactor, Coroutine& coro, struct pollfd* fds, nfds_t nfds, int timeout);
int     ppoll(Reactor& reactor, Coroutine& coro, struct pollfd* fds, nfds_t nfds, const struct timespec* const tmo_p, const sigset_t* const sigmask);
int     epoll_wait(Reactor& reactor, Coroutine& coro, int epfd, struct epoll_event* const events, const int maxevents, const int timeout);
int     epoll_pwait(Reactor& reactor, Coroutine& coro, int epfd, struct epoll_event* const events, const int maxevents, const int timeout, const sigset_t* const sigmask);

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

