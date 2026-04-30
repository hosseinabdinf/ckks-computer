cmake_minimum_required(VERSION 3.20)
project(ckks_computer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(CKKS_COMPUTER_BUILD_TESTS "Build ckks_computer tests" ON)
option(CKKS_COMPUTER_BUILD_BENCHMARKS "Build ckks_computer benchmarks" ON)

find_package(OpenFHE CONFIG QUIET)

add_library(ckks_computer_lib
  src/ckks_computer.cpp
)

target_include_directories(ckks_computer_lib PUBLIC src)

if(OpenFHE_FOUND)
  target_link_libraries(ckks_computer_lib PUBLIC openfhe)
endif()

add_executable(ckks_computer
  src/main.cpp
)

target_link_libraries(ckks_computer PRIVATE ckks_computer_lib)

if(CKKS_COMPUTER_BUILD_TESTS)
  enable_testing()
  add_executable(ckks_computer_tests
    tests/test_integer_computer.cpp
  )
  target_link_libraries(ckks_computer_tests PRIVATE ckks_computer_lib)
  add_test(NAME ckks_computer_tests COMMAND ckks_computer_tests)
endif()

if(CKKS_COMPUTER_BUILD_BENCHMARKS)
  add_executable(ckks_computer_bench
    bench/bench_integer_computer.cpp
  )
  target_link_libraries(ckks_computer_bench PRIVATE ckks_computer_lib)
endif()
