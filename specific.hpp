#pragma once

#include <stddef.h>

#ifndef YURCO_TRANSPARENCY

#include <stdlib.h>

namespace yurco
{
class Reactor;
class Coroutine;

__inline__  void        init(const size_t stack_size, const bool protect_stack) noexcept {}
__inline__  void        set_reactor(Reactor& reactor) noexcept {}
__inline__  void        set_coroutine(Coroutine& coro) noexcept {}
__inline__  Reactor&    get_reactor() noexcept {}
__inline__  Coroutine&  get_coroutine() noexcept {}

} // namespace yurco

#else

#include <pthread.h>

namespace yurco
{
class Reactor;
class Coroutine;

extern pthread_key_t reactor_key;
extern pthread_key_t coro_key;

            void        init(const size_t stack_size, const bool protect_stack=true) noexcept;
__inline__  void        set_reactor(Reactor& reactor) noexcept { pthread_setspecific(reactor_key, &reactor); }
__inline__  void        set_coroutine(Coroutine& coro) noexcept { pthread_setspecific(coro_key, &coro); }
__inline__  Reactor&    get_reactor() noexcept { return *reinterpret_cast<Reactor*>(pthread_getspecific(reactor_key)); }
__inline__  Coroutine&  get_coroutine() noexcept { return *reinterpret_cast<Coroutine*>(pthread_getspecific(coro_key)); }

            void        run(const size_t batch_size=16, const size_t events_at_once=1024) noexcept;
__inline__  void        terminate() noexcept;
template <class Func, class... Args>
__inline__  void        async(Func&& func, Args&&... args) noexcept;
__inline__  void        yield();
__inline__  void        suspend(const int fd, int events);

} // namespace yurco

#endif

