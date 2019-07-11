#pragma once

#include "specific.hpp"
#include "stack.hpp"
#include <unistd/context.hpp>
#include <vector>
#include <functional>
#include <type_traits>
#include <system_error>
#include <stddef.h>

extern "C"
    {
    int yurco_swapcontext(ucontext_t* oucp, const ucontext_t* ucp);
    }

namespace yurco
{

inline void swapcontext(ucontext_t* oucp, const ucontext_t* ucp)
    {
    const int ret = yurco_swapcontext(oucp, ucp);
    if (-1 == ret)
        throw std::system_error(errno, std::system_category(), "swapcontext()");
    }

class Coroutine
{
public:
                Coroutine(const Coroutine&) = delete;
template <class Func, class... Args>
inline          Coroutine(Stack&& stack, Func&& func, Args&&... args) noexcept;
inline  bool    is_completed() const noexcept;
inline  bool    is_running() const noexcept;
inline  void    yield();
        void    operator() ();
        void    operator() (const std::nothrow_t&) noexcept;
inline  void    set_exception(const std::exception_ptr& e) noexcept;
inline  const std::exception_ptr& get_exception() const noexcept;
inline  void    rethrow();
inline  Stack&& take_away_stack() noexcept;

protected:
union ptr2int
    {
    struct
        {
        int a;
        int b;
        } u;
    Coroutine* ptr;
    };

bool                m_completed = true;
std::exception_ptr  m_exception;
unistd::ucontext    m_context;
unistd::ucontext*   m_retpoint = nullptr;
Stack               m_stack;
std::function<void(Coroutine&)>   m_func;

inline  void        complete() noexcept;
inline  void        uncomplete() noexcept;
        void        entry() noexcept;
static  void        entry(int a, int b) noexcept;
template <bool pass_coro>
struct generate_func;
}; // class Coroutine

template <>
struct Coroutine::generate_func<true>
{
template <class Func, class... Args>
inline static std::function<void(Coroutine&)> get(Func&& func, Args&&... args) noexcept
    {
    return std::bind(std::forward<Func>(func), std::placeholders::_1, std::forward<Args>(args)...);
    }
};

template <>
struct Coroutine::generate_func<false>
{
template <class Func, class... Args>
inline static std::function<void(Coroutine&)> get(Func&& func, Args&&... args) noexcept
    {
    return std::bind(std::forward<Func>(func), std::forward<Args>(args)...);
    }
};

bool Coroutine::is_completed() const noexcept
    {
    return m_completed;
    }

void Coroutine::complete() noexcept
    {
    m_completed = true;
    }

void Coroutine::uncomplete() noexcept
    {
    m_completed = false;
    }

bool Coroutine::is_running() const noexcept
    {
    return m_retpoint != nullptr;
    }

void Coroutine::yield()
    {
    assert(is_running());
    assert(!std::current_exception());
    yurco::swapcontext(&m_context, m_retpoint);
    yurco::set_coroutine(*this);
    rethrow();
    }

void Coroutine::set_exception(const std::exception_ptr& e) noexcept
    {
    m_exception = e;
    }

const std::exception_ptr& Coroutine::get_exception() const noexcept
    {
    return m_exception;
    }

void Coroutine::rethrow()
    {
    if (m_exception)
        {
        std::exception_ptr e = get_exception();
        set_exception(nullptr);
        std::rethrow_exception(e);
        }
    }

Stack&& Coroutine::take_away_stack() noexcept
    {
    return std::move(m_stack);
    }

template <class Func, class... Args>
Coroutine::Coroutine(Stack&& stack, Func&& func, Args&&... args) noexcept:
        m_stack(std::forward<Stack>(stack)),
        m_func(generate_func<std::is_invocable_r_v<void, Func, Coroutine&, Args&...>>::get(std::forward<Func>(func), std::forward<Args>(args)...))
    {
    }

} // namespace yurco

