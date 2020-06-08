#pragma once

#include "coroutine.hpp"
#include "lock.hpp"
#include "stack.hpp"

#include <list>
#include <atomic>

/*
available state changes,    locks
ready->executing            executing, ready
executin->ready             executing, ready
executing->suspended        executing, suspended
suspended->ready            index, executing, ready, suspended
executing->terminate        executing
none->ready                 index, ready
*/

namespace yurco
{

class SimpleScheduler
{
protected:
enum class State
    {
    ready,
    suspended,
    executing
    }; // enum class State

struct coro_data
    {
    Coroutine   coro;
    State       state = State::ready;
    bool        want_suspend = false;
    bool        skip_suspend = false;
    template <class... Args>
    inline coro_data(Args&&... args) noexcept: coro(std::forward<Args>(args)...) {}
    }; // struct coro_data

public:
using coroutine_container = std::list<coro_data>;
using coroutine_iterator = coroutine_container::iterator;
using index_container = std::unordered_map<Coroutine*,coroutine_iterator>;

        SimpleScheduler(std::atomic<bool>& terminate, const size_t stack_size, const bool protect_stack) noexcept;
template <class Func, class... Args>
void    coroutine(Func&& func, Args&&... args) noexcept;

inline  bool    has_ready() noexcept;
inline  bool    has_suspended() noexcept;

bool    try_execute_one() noexcept;
void    resume_all() noexcept;
void    resume(Coroutine& coro) noexcept;
void    resume_many(std::vector<Coroutine*>& coros) noexcept;
void    suspend(Coroutine& coro) noexcept;

protected:
std::atomic<bool>&  m_terminate;
StackPool           m_stack_pool;
index_container     m_coroutine_index;
coroutine_container m_ready;
coroutine_container m_suspended;
coroutine_container m_executing;
lock_type           m_index_mutex;
lock_type           m_ready_mutex;
lock_type           m_suspended_mutex;
lock_type           m_executing_mutex;

coroutine_iterator  pop() noexcept;
void                remove_coroutine(coroutine_iterator coro) noexcept;
coroutine_iterator  get_coro_it(Coroutine& coro) noexcept;
}; // class SimpleScheduler

template <class Func, class... Args>
void SimpleScheduler::coroutine(Func&& func, Args&&... args) noexcept
    {
    Stack stack = m_stack_pool.pop();
    const lock_guard index_lock(m_index_mutex);
    const lock_guard ready_lock(m_ready_mutex);
    const coroutine_iterator coro_it = m_ready.emplace(m_ready.end(), std::move(stack), std::forward<Func>(func), std::forward<Args>(args)...);
    m_coroutine_index[&coro_it->coro] = coro_it;
    }

bool SimpleScheduler::has_ready() noexcept
    {
    const lock_guard lock(m_ready_mutex);
    return !m_ready.empty();
    }

bool SimpleScheduler::has_suspended() noexcept
    {
    const lock_guard lock(m_suspended_mutex);
    return !m_suspended.empty();
    }

} // namespace yurco

