#pragma once

#include <unistd/fd.hpp>

namespace yurco
{

class fd:
    public unistd::fd
{
private:
std::reference_wrapper<Reactor> m_reactor;

public:
using unistd::fd::native_type;
using unistd::fd::operator native_type;

inline      fd(yurco::Reactor& r) noexcept;
inline      fd(fd&& origin) noexcept;
inline      fd(const fd& origin);
inline      ~fd() noexcept; // std::terminate() at throw
inline yurco::Reactor& reactor();
inline size_t read(yurco::Coroutine& coro, void* buf, size_t count) __attribute__((warn_unused_result));
inline size_t write(yurco::Coroutine& coro, const void* buf, size_t count) __attribute__((warn_unused_result));
//        void    read(yurco::Coroutine& coro, yurco::fd& fd, std::vector<char>& buf);
//        size_t  write(yurco::Coroutine& coro, yurco::fd& fd, const std::vector<char>& buf) __attribute__((warn_unused_result));

//        void    read_all(yurco::Coroutine& coro, yurco::fd& fd, void* buf, size_t count);
//        void    write_all(yurco::Coroutine& coro, yurco::fd& fd, const void* buf, size_t count);
//        void    read_all(yurco::Coroutine& coro, yurco::fd& fd, std::vector<char>& buf);
//        void    write_all(yurco::Coroutine& coro, yurco::fd& fd, const std::vector<char>& buf);
inline fd   accept(yurco::Coroutine& coro, int flags = 0) __attribute__((warn_unused_result));
inline fd   accept(yurco::Coroutine& coro, ::sockaddr* addr, socklen_t* addrlen, int flags = 0) __attribute__((warn_unused_result));
inline void close();
inline int  close(const std::nothrow_t&) noexcept; // return errcode instead of throwing exception
inline static fd dup(yurco::Reactor& r, native_type val);            // construct unistd::fd using ::dup(val)
inline static fd nodup(yurco::Reactor& r, native_type val) noexcept; // construct unistd::fd without call ::dup(val)
};

} // namespace yurco

#include "fd.inc"

