#include "transparency.hpp"

#ifdef YURCO_TRANSPARENCY

extern "C"
{
int __wrap_select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, struct timeval* timeout) { return yurco::select(std::nothrow, *yurco::get_reactor(), *yurco::get_coroutine(), nfds, readfds, writefds, exceptfds, timeout); }
int __wrap_pselect(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const struct timespec* timeout, const sigset_t* sigmask) { return yurco::pselect(std::nothrow, *yurco::get_reactor(), *yurco::get_coroutine(), nfds, readfds, writefds, exceptfds, timeout, sigmask); }
int __wrap_poll(struct pollfd* fds, nfds_t nfds, int timeout)  { return yurco::poll(std::nothrow, *yurco::get_reactor(), *yurco::get_coroutine(), fds, nfds, timeout); }
int __wrap_ppoll(struct pollfd* fds, nfds_t nfds, const struct timespec* tmo_p, const sigset_t* sigmask) { return yurco::ppoll(std::nothrow, *yurco::get_reactor(), *yurco::get_coroutine(), fds, nfds, tmo_p, sigmask); }
int __wrap_epoll_wait(int epfd, struct epoll_event* events, int maxevents, int timeout) { return yurco::epoll_wait(std::nothrow, *yurco::get_reactor(), *yurco::get_coroutine(), epfd, events, maxevents, timeout ); }
int __wrap_epoll_pwait(int epfd, struct epoll_event* events, int maxevents, int timeout, const sigset_t* sigmask) { return yurco::epoll_pwait(std::nothrow, *yurco::get_reactor(), *yurco::get_coroutine(), epfd, events, maxevents, timeout, sigmask ); }

int __wrap_close(int fd) { return yurco::close(std::nothrow, *yurco::get_reactor(), fd); }
ssize_t __wrap_read(int fd, void* buf, size_t count) { return yurco::read(std::nothrow, *yurco::get_reactor(), *yurco::get_coroutine(), fd, buf, count); }
ssize_t __wrap_write(int fd, const void* buf, size_t count) { return yurco::write(std::nothrow, *yurco::get_reactor(), *yurco::get_coroutine(), fd, buf, count); }
int __wrap_connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen) { return yurco::connect(std::nothrow, *yurco::get_reactor(), *yurco::get_coroutine(), sockfd, addr, addrlen); }
int __wrap_accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen) { return yurco::accept(std::nothrow, *yurco::get_reactor(), *yurco::get_coroutine(), sockfd, addr, addrlen); }
int __wrap_accept4(int sockfd, struct sockaddr* addr, socklen_t* addrlen, int flags) { return yurco::accept(std::nothrow, *yurco::get_reactor(), *yurco::get_coroutine(), sockfd, addr, addrlen, flags); }
ssize_t __wrap_recv(int sockfd, void* buf, size_t len, int flags) { return yurco::recv(std::nothrow, *yurco::get_reactor(), *yurco::get_coroutine(), sockfd, buf, len, flags); }
ssize_t __wrap_recvfrom(int sockfd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen) { return yurco::recvfrom(std::nothrow, *yurco::get_reactor(), *yurco::get_coroutine(), sockfd, buf, len, flags, src_addr, addrlen); }
ssize_t __wrap_recvmsg(int sockfd, struct msghdr* msg, int flags) { return yurco::recvmsg(std::nothrow, *yurco::get_reactor(), *yurco::get_coroutine(), sockfd, msg, flags); }
ssize_t __wrap_send(int sockfd, const void* msg, size_t len, int flags) { return yurco::send(std::nothrow, *yurco::get_reactor(), *yurco::get_coroutine(), sockfd, msg, len, flags); }
ssize_t __wrap_sendto(int sockfd, const void* msg, size_t len, int flags, const struct sockaddr* to, socklen_t tolen) { return yurco::sendto(std::nothrow, *yurco::get_reactor(), *yurco::get_coroutine(), sockfd, msg, len, flags, to, tolen); }
ssize_t __wrap_sendmsg(int sockfd, const struct msghdr* msg, int flags) { return yurco::sendmsg(std::nothrow, *yurco::get_reactor(), *yurco::get_coroutine(), sockfd, msg, flags); }
} // extern "C"

#endif

