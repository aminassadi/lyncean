

add_custom_target(
    extern_lib
    COMMAND ${CMAKE_COMMAND} -E echo "Generatin bpf skeleton"
    COMMAND make
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/kern
)

set(SOURCE main.cpp)
#list(APPEND SOURCE pch.h)

add_executable(${PROJECT_NAME} ${SOURCE})