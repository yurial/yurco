#include "specific.hpp"

#ifdef YURCO_TRANSPARENCY

#include "reactor.hpp"
#include <mutex>
#include <memory>

namespace yurco
{

std::once_flag once_flag;
pthread_key_t reactor_key;
pthread_key_t coro_key;

static std::unique_ptr<Reactor> default_reactor;

__attribute__((constructor)) static
void init_specific()
    {
    auto init_once = [] () -> void
        {
        if (0 != ::pthread_key_create(&reactor_key, nullptr))
            abort();
        if (0 != ::pthread_key_create(&coro_key, nullptr))
            abort();
        };
    std::call_once(once_flag, init_once);
    }

void init(const size_t stack_size, const bool protect_stack) noexcept
    {
    init_specific();
    default_reactor = std::make_unique<Reactor>(stack_size, protect_stack);
    set_reactor(default_reactor.get());
    }

void run(const size_t batch_size, const size_t events_at_once) noexcept
    {
    default_reactor->run(batch_size, events_at_once);
    }

} // namespace yurco

#endif

