cmake_minimum_required(VERSION 3.22.1)
project(lyncean LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++20")

add_subdirectory(src)
add_subdirectory(test)

include_directories(../src/.output)
target_link_directories(${PROJECT_NAME} PRIVATE ../src/.output)
target_link_libraries(${PROJECT_NAME} PRIVATE libbpf.a elf z)