#pragma once

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>

#ifndef YURCO_TRANSPARENCY
#include <unistd.h>

extern "C"
{
__inline__  int     __real_close(int fd) { return ::close(fd); }
__inline__  ssize_t __real_read(int fd, void* buf, size_t count) { return ::read(fd, buf, count); }
__inline__  ssize_t __real_write(int fd, const void* buf, size_t count) { return ::write(fd, buf, count); }
__inline__  int     __real_connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen) { return ::connect(sockfd, addr, addrlen); }
__inline__  int     __real_accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen) { return ::accept(sockfd, addr, addrlen); }
__inline__  int     __real_accept4(int sockfd, struct sockaddr* addr, socklen_t* addrlen, int flags) { return ::accept4(sockfd, addr, addrlen, flags); }
__inline__  ssize_t __real_recv(int sockfd, void* buf, size_t len, int flags) { return ::recv(sockfd, buf, len, flags); }
__inline__  ssize_t __real_recvfrom(int sockfd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen) { return ::recvfrom(sockfd, buf, len, flags, src_addr, addrlen); }
__inline__  ssize_t __real_recvmsg(int sockfd, struct msghdr* msg, int flags) { return ::recvmsg(sockfd, msg, flags); }
__inline__  ssize_t __real_send(int sockfd, const void* msg, size_t len, int flags) { return ::send(sockfd, msg, len, flags); }
__inline__  ssize_t __real_sendto(int sockfd, const void* msg, size_t len, int flags, const struct sockaddr* to, socklen_t tolen) { return ::sendto(sockfd, msg, len, flags, to, tolen); }
__inline__  ssize_t __real_sendmsg(int sockfd, const struct msghdr* msg, int flags) { return ::sendmsg(sockfd, msg, flags); }
}

#else

#include "operations.hpp"

extern "C"
{
int     __real_close(int fd);
ssize_t __real_read(int fd, void* buf, size_t count);
ssize_t __real_write(int fd, const void* buf, size_t count);
int     __real_connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen);
int     __real_accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen);
int     __real_accept4(int sockfd, struct sockaddr* addr, socklen_t* addrlen, int flags);
ssize_t __real_recv(int sockfd, void* buf, size_t len, int flags);
ssize_t __real_recvfrom(int sockfd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen);
ssize_t __real_recvmsg(int sockfd, struct msghdr* msg, int flags);
ssize_t __real_send(int sockfd, const void* msg, size_t len, int flags);
ssize_t __real_sendto(int sockfd, const void* msg, size_t len, int flags, const struct sockaddr* to, socklen_t tolen);
ssize_t __real_sendmsg(int sockfd, const struct msghdr* msg, int flags);


int     __wrap_close(int fd);
ssize_t __wrap_read(int fd, void* buf, size_t count);
ssize_t __wrap_write(int fd, const void* buf, size_t count);
int     __wrap_connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen);
int     __wrap_accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen);
int     __wrap_accept4(int sockfd, struct sockaddr* addr, socklen_t* addrlen, int flags);
ssize_t __wrap_recv(int sockfd, void* buf, size_t len, int flags);
ssize_t __wrap_recvfrom(int sockfd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen);
ssize_t __wrap_recvmsg(int sockfd, struct msghdr* msg, int flags);
ssize_t __wrap_send(int sockfd, const void* msg, size_t len, int flags);
ssize_t __wrap_sendto(int sockfd, const void* msg, size_t len, int flags, const struct sockaddr* to, socklen_t tolen);
ssize_t __wrap_sendmsg(int sockfd, const struct msghdr* msg, int flags);
}

#endif
