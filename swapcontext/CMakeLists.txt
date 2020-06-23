enable_language(ASM)
add_library(swapcontext STATIC EXCLUDE_FROM_ALL "${CMAKE_HOST_SYSTEM_PROCESSOR}.S")
