#pragma once

#include <exception>

namespace yurco
{

class terminate_exception:
    public std::exception
{
public:
    terminate_exception() = default;
    terminate_exception(const terminate_exception&) = default;
    terminate_exception(terminate_exception&&) = default;
}; // class terminate_exception

} // namespace yurco

