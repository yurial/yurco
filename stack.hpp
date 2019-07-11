#pragma once

#include "lock.hpp"
#include <unistd/unistd.hpp>
#include <list>
#include <vector>
#include <memory>
#include <functional>
#include <assert.h>

namespace yurco
{

class Stack
{
public:
inline          Stack(const size_t size, const bool protect=true);
                Stack(const Stack&) = delete;
                Stack(Stack&&) = default;

inline  char*   data() const noexcept { return m_data; }
inline  size_t  size() const noexcept { return m_size; }
protected:
using ptr_type = std::unique_ptr<char[], std::function<void(char*)>>;
ptr_type        m_ptr;
char*           m_data = nullptr;
size_t          m_size = 0;
}; // class Stack

Stack::Stack(const size_t size, const bool protect):
        m_size(size)
    {
    const size_t page_size = sysconf(_SC_PAGE_SIZE);
    assert(size % page_size == 0); // "stack should be multiple of PAGE_SIZE"
    const size_t real_size = protect? 2*page_size + size : size;
    m_ptr = ptr_type(
        static_cast<char*>(unistd::mmap(nullptr, real_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN | MAP_STACK | MAP_NORESERVE, -1, 0)),
        [size](char* ptr) { unistd::munmap(ptr, size); }
        );
    m_data = protect? m_ptr.get() + page_size : m_ptr.get();
    unistd::mprotect(m_data, m_size, PROT_READ | PROT_WRITE);
    }

class StackPool
{
public:
inline         StackPool(const size_t stack_size, const bool protect=true): m_protect(protect), m_stack_size(stack_size) {}
inline Stack   pop();
inline void    push(Stack&& stack) { const lock_guard lock(m_mutex); m_pool.emplace_back(std::move(stack)); }

protected:
bool                m_protect;
lock_type           m_mutex;
size_t              m_stack_size;
std::list<Stack>    m_pool;
}; // class StackPool

Stack StackPool::pop()
    {
    const lock_guard lock(m_mutex);
    if (m_pool.empty())
        return Stack(m_stack_size, m_protect);
    Stack stack = std::move(m_pool.front());
    m_pool.pop_front();
    return stack;
    }

} // namespace yurco

