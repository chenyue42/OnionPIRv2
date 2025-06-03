# OnionPIR version 2

### Preliminaries

We ran our code on AWS c5n.9xlarge machine, which runs Ubuntu 22.04. This machine uses `Intel(R) Xeon(R) Platinum 8124M CPU @ 3.00GHz`, which allows us to use AVX2 and AVX512 to boost NTT related computation. 

We use c++20 and `GCC 11.4.0` for compilation.

### Installation

1. OnionPIR v2 is using Microsoft SEAL library with some modification of their implementations. Hence, we forked their repository and applied changes. To run OnionPIRv2, you need to install  **[SEAL-For-OnionPIR](https://github.com/helloboyxxx/SEAL-For-OnionPIR)** first. Installation should be easy. You can run the following commands to build and install SEAL globally on your machine.

```
git clone https://github.com/helloboyxxx/SEAL-For-OnionPIR.git
cd SEAL-For-OnionPIR/
mkdir build && cmake ..
sudo make install
```

2. Optionally, you can install Eigen3 since we did some test on matrix-matrix multiplication using this third party. You can install is by `sudo apt install libeigen3-dev`.
3. You can use -DUSE_HEXL=OFF to turn off HEXL related tests.
4. After installation, set `CMAKE_PREFIX_PATH` to the library's location. Separate versions of the library can be used for debugging and benchmarking. To run as a debug build, set -DCMAKE_BUILD_TYPE=Debug as a cmake option. To run benchmarks, set -DCMAKE_BUILD_TYPE=Benchmark. The benchmark build type is used by default. (It is fine to keep this CMAKE_PREFIX_PATH unchanged. ) Now, you can build and run OnionPIRv2 using: 

```
mkdir build && cd build
cmake ..
make && ./Onion-PIR
```

If you want to turn on the debug mode and read detailed output or use the profiling tools, you can run:

```
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug 
make && ./Onion-PIR
```



### Tips

- Currently, most of the parameters can be adjusted in `src/includes/database_constants.h`. 
- You can use `clangd` when reading the code. The `compile_commands.json` file will be automatically generated after cmake.
- You can install the [Better Comments](https://marketplace.visualstudio.com/items?itemName=aaron-bond.better-comments) extension to highlight the TODO or remarked comments.
- The code also runs for clang, but we use GCC unroll in some places. Please change those lines if you want to test optimal throughput.
