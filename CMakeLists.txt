cmake_minimum_required(VERSION 3.13)

# Set build type to Benchmark if not specified
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Benchmark)
endif()

# Compiler picked up from PATH. Load the desired toolchain before running
# cmake (e.g. `module load gcc/13.3.0`). Override with -DCMAKE_CXX_COMPILER=...
# if you want to pin a specific binary.

# Ask every target in this project to compile as C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)   # fail if the compiler can't do C++20
set(CMAKE_CXX_EXTENSIONS  OFF)        # use -std=c++20, not gnu++20

# Automatically enables all available optimizations for your local machine, including AVX2 and AVX512
set(CMAKE_CXX_FLAGS "-O3 -MD -march=native -mtune=native")  # Enable all optimizations

# Add perf when building in Debug mode
if (CMAKE_BUILD_TYPE MATCHES Debug)
    set(CMAKE_CXX_FLAGS "-O2 -MD -pg -march=native -mtune=native")  # Enable profiling flags
endif()


# Option to enable Intel HEXL optimizations. Default is ON.
option(USE_HEXL "Enable Intel HEXL optimizations" ON)
if (USE_HEXL)
    message(STATUS "HEXL support enabled.")
    add_compile_definitions(ONIONPIR_USE_HEXL)
    
    # Set HEXL installation path
    set(HEXL_DIR "/u/yuec12/OnionPIRv2/hexl_install/lib64/cmake/hexl-1.2.6")
    
    # Find HEXL package
    find_package(HEXL REQUIRED)
    if(HEXL_FOUND)
        message(STATUS "HEXL found at: ${HEXL_DIR}")
    else()
        message(FATAL_ERROR "HEXL not found. Please install HEXL or disable USE_HEXL option.")
    endif()
else()
    message(STATUS "HEXL support disabled.")
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

# Build-time selectors for K-RNS variant testing. Override on the cmake line:
#   cmake -DACTIVE_CONFIG=CONFIG_N2048_M28_28 -DKS_VARIANT=KS_BV -DEP_VARIANT=EP_VARIANT ..
# Defaults are picked up from src/includes/database_constants.h when unset.
foreach(opt ACTIVE_CONFIG KS_VARIANT EP_VARIANT)
    if (DEFINED ${opt})
        message(STATUS "${opt} = ${${opt}}")
        add_compile_definitions(${opt}=${${opt}})
    endif()
endforeach()


# Automatically find all source files in src/
file(GLOB_RECURSE SRC_FILES src/*.cpp)
add_executable(Onion-PIR ${SRC_FILES})

# Link HEXL if enabled
if (USE_HEXL AND HEXL_FOUND)
    target_link_libraries(Onion-PIR PUBLIC HEXL::hexl)
endif()

# Include directories
target_include_directories(Onion-PIR PUBLIC src/includes)
