#pragma once
#include <atomic>
#include <stdlib.h>

namespace yurco
{

#ifndef SINGLE_THREAD

class lock_type
{
public:
inline void lock() noexcept { while(!try_lock()); }
inline void unlock() noexcept { m_spin.clear(std::memory_order_release); }
inline bool try_lock() noexcept { return !m_spin.test_and_set(std::memory_order_acquire); }
protected:
std::atomic_flag    m_spin = ATOMIC_FLAG_INIT;
}; // class spin

#else

class lock_type
{
public:
inline void lock() noexcept {}
inline void unlock() noexcept {}
inline bool try_lock() noexcept { return true; }
}; // class lock_type

#endif

class lock_guard
{
protected:
lock_type& m_mutex;

public:
inline  lock_guard(lock_type& mutex) noexcept: m_mutex(mutex) { mutex.lock(); }
inline ~lock_guard() noexcept { m_mutex.unlock(); }
}; // lock_guard

} // namespace yurco

