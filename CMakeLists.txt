cmake_minimum_required(VERSION 3.13)

# Set build type to Benchmark if not specified
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Benchmark)
endif()

# Automatically enables all available optimizations for your local machine, including AVX2 and AVX512
set(CMAKE_CXX_FLAGS "-O3 -pg -MD -march=native -mtune=native")  # Enable all optimizations


# Add perf when building in Debug mode
if (CMAKE_BUILD_TYPE MATCHES Debug)
    set(CMAKE_CXX_FLAGS "-O2 -MD -pg -march=native -mtune=native")  # Enable profiling flags
endif()

option(NOAVX512 "Disable AVX-512" OFF)
option(NOAVX2 "Disable AVX2" OFF)
if (NOAVX512)
    message("Disabling AVX-512")
    add_compile_options(-mno-avx512f)
endif()
if (NOAVX2)
    message("Disabling AVX2")
    add_compile_options(-mno-avx2)
endif()

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -D_DEBUG")
set(IS_BENCHMARK_BUILD CMAKE_BUILD_TYPE STREQUAL "Benchmark")
if (${IS_BENCHMARK_BUILD})
    add_compile_definitions(_BENCHMARK)
endif ()
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
project(Onion-PIR)

# Automatically find all source files in src/
file(GLOB_RECURSE SRC_FILES src/*.cpp)
add_executable(Onion-PIR ${SRC_FILES})

# Find and link SEAL library
find_package(SEAL 4.1 REQUIRED)
target_link_libraries(Onion-PIR PUBLIC SEAL::seal)

# Attempt to find Eigen3 quietly
find_package(Eigen3 3.3 QUIET)

if(Eigen3_FOUND)
    message(STATUS "Eigen3 found. Enabling Eigen-specific functionality.")
    target_link_libraries(Onion-PIR PUBLIC Eigen3::Eigen)
    target_compile_definitions(Onion-PIR PUBLIC HAVE_EIGEN)
else()
    message(WARNING "Eigen3 not found. Skipping Eigen-specific code.")
    target_compile_definitions(Onion-PIR PUBLIC SKIP_EIGEN)
endif()

# Include directories
target_include_directories(Onion-PIR PUBLIC src/includes)
