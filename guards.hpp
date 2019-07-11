#pragma once

namespace yurco
{

template <class T>
class unlock_guard
{
public:
inline  unlock_guard(T& mutex): m_mutex(mutex) { m_mutex.unlock(); }
inline ~unlock_guard() { m_mutex.lock(); }

protected:
T&      m_mutex;
}; // class unlock_guard

template <class T>
class swap_guard
{
public:
inline  swap_guard(T& v1, T& v2): m_v1(v1), m_v2(v2) { std::swap(m_v1, m_v2); }
inline ~swap_guard() { std::swap(m_v1, m_v2); }

protected:
T&      m_v1;
T&      m_v2;
}; // class swap_guard

} // namespace yurco

