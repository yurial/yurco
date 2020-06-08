#include "scheduler.hpp"
#include "exceptions.hpp"

namespace yurco
{

SimpleScheduler::SimpleScheduler(std::atomic<bool>& terminate, const size_t stack_size, const bool protect_stack) noexcept:
        m_terminate(terminate),
        m_stack_pool(stack_size, protect_stack)
    {
    }

/* always remove under lock,
   always remove from m_executing */
void SimpleScheduler::remove_coroutine(coroutine_iterator coro_it) noexcept
    {
        {
        const lock_guard lock(m_index_mutex);
        m_coroutine_index.erase(&coro_it->coro);
        }
    coroutine_container tmp;
        {
        const lock_guard lock(m_executing_mutex);
        tmp.splice(tmp.end(), m_executing, coro_it);
        }
    m_stack_pool.push(std::move(coro_it->coro.take_away_stack()));
    tmp.erase(coro_it);
    }

SimpleScheduler::coroutine_iterator SimpleScheduler::pop() noexcept
    {
    const lock_guard executing_lock(m_executing_mutex);
    const lock_guard ready_lock(m_ready_mutex);
    const coroutine_iterator coro_it = m_ready.begin();
    if (coro_it != m_ready.end())
        {
        m_executing.splice(m_executing.end(), m_ready, coro_it);
        coro_it->state = State::executing;
        }
    return coro_it;
    }

bool SimpleScheduler::try_execute_one() noexcept
    {
    const coroutine_iterator coro_it = pop();
    if (coro_it == m_ready.end())
        return false;

    coro_it->want_suspend = false;
    coro_it->skip_suspend = false;
    if (m_terminate.load(std::memory_order_relaxed))
        coro_it->coro.set_exception(std::make_exception_ptr(terminate_exception()));
    coro_it->coro(std::nothrow);

    if (coro_it->coro.is_completed())
        {
        remove_coroutine(coro_it);
        return true;
        }

    const lock_guard executing_lock(m_executing_mutex);
    if (!coro_it->want_suspend || coro_it->skip_suspend)
        {
        const lock_guard lock(m_ready_mutex);
        m_ready.splice(m_ready.end(), m_executing, coro_it);
        coro_it->state = State::ready;
        }
    else
        {
        const lock_guard lock(m_suspended_mutex);
        m_suspended.splice(m_suspended.end(), m_executing, coro_it);
        coro_it->state = State::suspended;
        }
    return true;
    }

void SimpleScheduler::resume_all() noexcept
    {
    m_ready_mutex.lock();
    m_suspended_mutex.lock();
    for (auto coro_it = m_suspended.begin(); coro_it != m_suspended.end();)
        {
        const auto cur = coro_it++;
        m_ready.splice(m_ready.end(), m_suspended, cur);
        cur->state = State::ready;
        }
    m_suspended_mutex.unlock();
    m_ready_mutex.unlock();
    }

void SimpleScheduler::resume(Coroutine& coro) noexcept
    {
    const lock_guard executing_lock(m_executing_mutex);
    const lock_guard index_lock(m_index_mutex);
    const auto index_it = m_coroutine_index.find(&coro);
    if (m_coroutine_index.end() == index_it)
        return;
    const auto coro_it = index_it->second;
    switch (coro_it->state)
        {
        case State::executing:
            coro_it->skip_suspend = true;
            break;
        case State::suspended:
            {
            const lock_guard ready_lock(m_ready_mutex);
            const lock_guard suspended_lock(m_suspended_mutex);
            m_ready.splice(m_ready.end(), m_suspended, coro_it);
            coro_it->state = State::ready;
            }
            break;
        case State::ready:
            break;
        }
    }

void SimpleScheduler::resume_many(std::vector<Coroutine*>& coros) noexcept
    {
    const lock_guard index_lock(m_index_mutex);
    const lock_guard executing_lock(m_executing_mutex);
    const lock_guard ready_lock(m_ready_mutex);
    const lock_guard suspended_lock(m_suspended_mutex);
    for (const auto coro : coros)
        {
        const auto index_it = m_coroutine_index.find(coro);
        if (m_coroutine_index.end() == index_it)
            return;
        const auto coro_it = index_it->second;
        switch (coro_it->state)
            {
            case State::executing:
                coro_it->skip_suspend = true;
                break;
            case State::suspended:
                {
                m_ready.splice(m_ready.end(), m_suspended, coro_it);
                coro_it->state = State::ready;
                }
                break;
            case State::ready:
                break;
            }
        }
    }

SimpleScheduler::coroutine_iterator SimpleScheduler::get_coro_it(Coroutine& coro) noexcept
    {
    const lock_guard lock(m_index_mutex);
    const auto it = m_coroutine_index.find(&coro);
    assert(m_coroutine_index.end() != it);
    return it->second;
    }

void SimpleScheduler::suspend(Coroutine& coro) noexcept
    {
    const coroutine_iterator coro_it = get_coro_it(coro);
    coro_it->want_suspend = true;
    }

} // namespace yurco
