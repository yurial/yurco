#include "coroutine.hpp"
#include "guards.hpp"

#include <assert.h>

namespace yurco
{

void Coroutine::entry(int a, int b) noexcept
    {
    ptr2int p;
    p.u.a = a;
    p.u.b = b;
    Coroutine* ctx = p.ptr;
    ctx->entry();
    }

void Coroutine::entry() noexcept
    {
    try
        {
        if (!get_exception())
            {
            yurco::set_coroutine(this);
            m_func(*this);
            }
        }
    catch (...)
        {
        set_exception(std::current_exception());
        }
    complete();
    for (;;)
        yield();
    }

void Coroutine::operator() ()
    {
    assert(!is_running());
    this->operator () (std::nothrow);
    rethrow();
    }

void Coroutine::operator() (const std::nothrow_t&) noexcept
    {
    assert(!is_running());
    if (is_completed())
        {
        ptr2int p;
        p.ptr = this;
        void (*func)(int a, int b) = &Coroutine::entry;
        m_context = unistd::makecontext(m_stack.data(), m_stack.size(), reinterpret_cast<void (*)()>(func), p.u.a, p.u.b);
        uncomplete();
        }
    //
        {
        unistd::ucontext retpoint;
        unistd::ucontext* tmp = &retpoint;
        swap_guard<unistd::ucontext*> guard(m_retpoint, tmp);
        Coroutine* old_coro = yurco::get_coroutine();
        yurco::swapcontext(&retpoint, &m_context);
        yurco::set_coroutine(old_coro);
        }
    }

} // namespace yurco

