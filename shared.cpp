// This file automaticaly generated by gen.py

#include <stdlib.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <poll.h>

#include "transparency.hpp"

extern "C"
{
typedef int (*select_type)(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, struct timeval* timeout);
typedef int (*pselect_type)(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const struct timespec* timeout, const sigset_t* sigmask);
typedef int (*poll_type)(struct pollfd* fds, nfds_t nfds, int timeout);
typedef int (*ppoll_type)(struct pollfd* fds, nfds_t nfds, const struct timespec* tmo_p, const sigset_t* sigmask);
typedef int (*epoll_wait_type)(int epfd, struct epoll_event* events, int maxevents, int timeout);
typedef int (*epoll_pwait_type)(int epfd, struct epoll_event* events, int maxevents, int timeout, const sigset_t* sigmask);
typedef int (*close_type)(int fd);
typedef ssize_t (*read_type)(int fd, void* buf, size_t count);
typedef ssize_t (*write_type)(int fd, const void* buf, size_t count);
typedef int (*connect_type)(int sockfd, const struct sockaddr* addr, socklen_t addrlen);
typedef int (*accept_type)(int sockfd, struct sockaddr* addr, socklen_t* addrlen);
typedef int (*accept4_type)(int sockfd, struct sockaddr* addr, socklen_t* addrlen, int flags);
typedef ssize_t (*recv_type)(int sockfd, void* buf, size_t len, int flags);
typedef ssize_t (*recvfrom_type)(int sockfd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen);
typedef ssize_t (*recvmsg_type)(int sockfd, struct msghdr* msg, int flags);
typedef ssize_t (*send_type)(int sockfd, const void* msg, size_t len, int flags);
typedef ssize_t (*sendto_type)(int sockfd, const void* msg, size_t len, int flags, const struct sockaddr* to, socklen_t tolen);
typedef ssize_t (*sendmsg_type)(int sockfd, const struct msghdr* msg, int flags);

select_type select_ptr = nullptr;
pselect_type pselect_ptr = nullptr;
poll_type poll_ptr = nullptr;
ppoll_type ppoll_ptr = nullptr;
epoll_wait_type epoll_wait_ptr = nullptr;
epoll_pwait_type epoll_pwait_ptr = nullptr;
close_type close_ptr = nullptr;
read_type read_ptr = nullptr;
write_type write_ptr = nullptr;
connect_type connect_ptr = nullptr;
accept_type accept_ptr = nullptr;
accept4_type accept4_ptr = nullptr;
recv_type recv_ptr = nullptr;
recvfrom_type recvfrom_ptr = nullptr;
recvmsg_type recvmsg_ptr = nullptr;
send_type send_ptr = nullptr;
sendto_type sendto_ptr = nullptr;
sendmsg_type sendmsg_ptr = nullptr;

int __real_select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, struct timeval* timeout) { return select_ptr(nfds, readfds, writefds, exceptfds, timeout); }
int __real_pselect(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const struct timespec* timeout, const sigset_t* sigmask) { return pselect_ptr(nfds, readfds, writefds, exceptfds, timeout, sigmask); }
int __real_poll(struct pollfd* fds, nfds_t nfds, int timeout) { return poll_ptr(fds, nfds, timeout); }
int __real_ppoll(struct pollfd* fds, nfds_t nfds, const struct timespec* tmo_p, const sigset_t* sigmask) { return ppoll_ptr(fds, nfds, tmo_p, sigmask); }
int __real_epoll_wait(int epfd, struct epoll_event* events, int maxevents, int timeout) { return epoll_wait_ptr(epfd, events, maxevents, timeout); }
int __real_epoll_pwait(int epfd, struct epoll_event* events, int maxevents, int timeout, const sigset_t* sigmask) { return epoll_pwait_ptr(epfd, events, maxevents, timeout, sigmask); }
int __real_close(int fd) { return close_ptr(fd); }
ssize_t __real_read(int fd, void* buf, size_t count) { return read_ptr(fd, buf, count); }
ssize_t __real_write(int fd, const void* buf, size_t count) { return write_ptr(fd, buf, count); }
int __real_connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen) { return connect_ptr(sockfd, addr, addrlen); }
int __real_accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen) { return accept_ptr(sockfd, addr, addrlen); }
int __real_accept4(int sockfd, struct sockaddr* addr, socklen_t* addrlen, int flags) { return accept4_ptr(sockfd, addr, addrlen, flags); }
ssize_t __real_recv(int sockfd, void* buf, size_t len, int flags) { return recv_ptr(sockfd, buf, len, flags); }
ssize_t __real_recvfrom(int sockfd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen) { return recvfrom_ptr(sockfd, buf, len, flags, src_addr, addrlen); }
ssize_t __real_recvmsg(int sockfd, struct msghdr* msg, int flags) { return recvmsg_ptr(sockfd, msg, flags); }
ssize_t __real_send(int sockfd, const void* msg, size_t len, int flags) { return send_ptr(sockfd, msg, len, flags); }
ssize_t __real_sendto(int sockfd, const void* msg, size_t len, int flags, const struct sockaddr* to, socklen_t tolen) { return sendto_ptr(sockfd, msg, len, flags, to, tolen); }
ssize_t __real_sendmsg(int sockfd, const struct msghdr* msg, int flags) { return sendmsg_ptr(sockfd, msg, flags); }

int select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, struct timeval* timeout) { return __wrap_select(nfds, readfds, writefds, exceptfds, timeout); }
int __select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, struct timeval* timeout) { return __wrap_select(nfds, readfds, writefds, exceptfds, timeout); }
int pselect(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const struct timespec* timeout, const sigset_t* sigmask) { return __wrap_pselect(nfds, readfds, writefds, exceptfds, timeout, sigmask); }
int __pselect(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const struct timespec* timeout, const sigset_t* sigmask) { return __wrap_pselect(nfds, readfds, writefds, exceptfds, timeout, sigmask); }
int poll(struct pollfd* fds, nfds_t nfds, int timeout) { return __wrap_poll(fds, nfds, timeout); }
int __poll(struct pollfd* fds, nfds_t nfds, int timeout) { return __wrap_poll(fds, nfds, timeout); }
int ppoll(struct pollfd* fds, nfds_t nfds, const struct timespec* tmo_p, const sigset_t* sigmask) { return __wrap_ppoll(fds, nfds, tmo_p, sigmask); }
int __ppoll(struct pollfd* fds, nfds_t nfds, const struct timespec* tmo_p, const sigset_t* sigmask) { return __wrap_ppoll(fds, nfds, tmo_p, sigmask); }
int epoll_wait(int epfd, struct epoll_event* events, int maxevents, int timeout) { return __wrap_epoll_wait(epfd, events, maxevents, timeout); }
int __epoll_wait(int epfd, struct epoll_event* events, int maxevents, int timeout) { return __wrap_epoll_wait(epfd, events, maxevents, timeout); }
int epoll_pwait(int epfd, struct epoll_event* events, int maxevents, int timeout, const sigset_t* sigmask) { return __wrap_epoll_pwait(epfd, events, maxevents, timeout, sigmask); }
int __epoll_pwait(int epfd, struct epoll_event* events, int maxevents, int timeout, const sigset_t* sigmask) { return __wrap_epoll_pwait(epfd, events, maxevents, timeout, sigmask); }
int close(int fd) { return __wrap_close(fd); }
int __close(int fd) { return __wrap_close(fd); }
ssize_t read(int fd, void* buf, size_t count) { return __wrap_read(fd, buf, count); }
ssize_t __read(int fd, void* buf, size_t count) { return __wrap_read(fd, buf, count); }
ssize_t write(int fd, const void* buf, size_t count) { return __wrap_write(fd, buf, count); }
ssize_t __write(int fd, const void* buf, size_t count) { return __wrap_write(fd, buf, count); }
int connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen) { return __wrap_connect(sockfd, addr, addrlen); }
int __connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen) { return __wrap_connect(sockfd, addr, addrlen); }
int accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen) { return __wrap_accept(sockfd, addr, addrlen); }
int __accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen) { return __wrap_accept(sockfd, addr, addrlen); }
int accept4(int sockfd, struct sockaddr* addr, socklen_t* addrlen, int flags) { return __wrap_accept4(sockfd, addr, addrlen, flags); }
int __accept4(int sockfd, struct sockaddr* addr, socklen_t* addrlen, int flags) { return __wrap_accept4(sockfd, addr, addrlen, flags); }
ssize_t recv(int sockfd, void* buf, size_t len, int flags) { return __wrap_recv(sockfd, buf, len, flags); }
ssize_t __recv(int sockfd, void* buf, size_t len, int flags) { return __wrap_recv(sockfd, buf, len, flags); }
ssize_t recvfrom(int sockfd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen) { return __wrap_recvfrom(sockfd, buf, len, flags, src_addr, addrlen); }
ssize_t __recvfrom(int sockfd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen) { return __wrap_recvfrom(sockfd, buf, len, flags, src_addr, addrlen); }
ssize_t recvmsg(int sockfd, struct msghdr* msg, int flags) { return __wrap_recvmsg(sockfd, msg, flags); }
ssize_t __recvmsg(int sockfd, struct msghdr* msg, int flags) { return __wrap_recvmsg(sockfd, msg, flags); }
ssize_t send(int sockfd, const void* msg, size_t len, int flags) { return __wrap_send(sockfd, msg, len, flags); }
ssize_t __send(int sockfd, const void* msg, size_t len, int flags) { return __wrap_send(sockfd, msg, len, flags); }
ssize_t sendto(int sockfd, const void* msg, size_t len, int flags, const struct sockaddr* to, socklen_t tolen) { return __wrap_sendto(sockfd, msg, len, flags, to, tolen); }
ssize_t __sendto(int sockfd, const void* msg, size_t len, int flags, const struct sockaddr* to, socklen_t tolen) { return __wrap_sendto(sockfd, msg, len, flags, to, tolen); }
ssize_t sendmsg(int sockfd, const struct msghdr* msg, int flags) { return __wrap_sendmsg(sockfd, msg, flags); }
ssize_t __sendmsg(int sockfd, const struct msghdr* msg, int flags) { return __wrap_sendmsg(sockfd, msg, flags); }
int __close_nocancel(int fd) { return __wrap_close(fd); }

__attribute__((constructor)) static
void init()
    {
    select_ptr = reinterpret_cast<select_type>(dlsym(RTLD_NEXT, "select"));
    pselect_ptr = reinterpret_cast<pselect_type>(dlsym(RTLD_NEXT, "pselect"));
    poll_ptr = reinterpret_cast<poll_type>(dlsym(RTLD_NEXT, "poll"));
    ppoll_ptr = reinterpret_cast<ppoll_type>(dlsym(RTLD_NEXT, "ppoll"));
    epoll_wait_ptr = reinterpret_cast<epoll_wait_type>(dlsym(RTLD_NEXT, "epoll_wait"));
    epoll_pwait_ptr = reinterpret_cast<epoll_pwait_type>(dlsym(RTLD_NEXT, "epoll_pwait"));
    close_ptr = reinterpret_cast<close_type>(dlsym(RTLD_NEXT, "close"));
    read_ptr = reinterpret_cast<read_type>(dlsym(RTLD_NEXT, "read"));
    write_ptr = reinterpret_cast<write_type>(dlsym(RTLD_NEXT, "write"));
    connect_ptr = reinterpret_cast<connect_type>(dlsym(RTLD_NEXT, "connect"));
    accept_ptr = reinterpret_cast<accept_type>(dlsym(RTLD_NEXT, "accept"));
    accept4_ptr = reinterpret_cast<accept4_type>(dlsym(RTLD_NEXT, "accept4"));
    recv_ptr = reinterpret_cast<recv_type>(dlsym(RTLD_NEXT, "recv"));
    recvfrom_ptr = reinterpret_cast<recvfrom_type>(dlsym(RTLD_NEXT, "recvfrom"));
    recvmsg_ptr = reinterpret_cast<recvmsg_type>(dlsym(RTLD_NEXT, "recvmsg"));
    send_ptr = reinterpret_cast<send_type>(dlsym(RTLD_NEXT, "send"));
    sendto_ptr = reinterpret_cast<sendto_type>(dlsym(RTLD_NEXT, "sendto"));
    sendmsg_ptr = reinterpret_cast<sendmsg_type>(dlsym(RTLD_NEXT, "sendmsg"));
    yurco::init(1024*1024);
    } // init

} // extern "C"
