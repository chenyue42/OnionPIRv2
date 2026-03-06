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

2. You can use -DUSE_HEXL=OFF to turn off HEXL related tests.
4. After installation, set `CMAKE_PREFIX_PATH` to the library's location. (It is fine to keep this `CMAKE_PREFIX_PATH` unchanged.) Now, you can build and run OnionPIRv2 using `run.py`:

```
mkdir build
python run.py
```

### Usage

`run.py` handles building with the correct compile flags and running the binary.

```
python run.py [options]
```

| Option | Description |
|---|---|
| `-v`, `--verbose` | Build in Debug mode (enables `DEBUG_PRINT` at compile time) |
| `--no-compress` | Run PIR without query compression/decompression |
| `-t NAME`, `--test NAME` | Test to run (default: `pir`). See available tests below |
| `-o FILE`, `--output FILE` | Write results to file (bare name goes to `outputs/`) |
| `-j N`, `--jobs N` | Parallel make jobs (default: all cores) |
| `--build-only` | Build without running |
| `-h`, `--help` | Show help message |

**Examples:**

```bash
# Benchmark mode (default) — DEBUG_PRINT compiled out for max performance
python run.py

# Verbose/debug mode — recompiles with DEBUG_PRINT enabled
python run.py -v

# Without compression, save results to outputs/results.txt
python run.py --no-compress -o no-compress.txt

# Just build, don't run
python run.py --build-only

# Run a specific test
python run.py -t bfv
python run.py -t fst_dim -v
```

**Available tests:** `pir` (default), `bfv`, `serial`, `ext_prod`, `ext_prod_mux`, `fst_dim`, `batch_decomp`, `fast_expand`, `raw_pt_ct`, `decrypt_mod_q`, `mod_switch`, `sk_mod_switch`, `db_shape`, `cpu_info`

You can also build and run manually with CMake:

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug   # or Benchmark (default)
make && ./Onion-PIR [--no-compress]
```



### Tips

- Currently, most of the parameters can be adjusted in `src/includes/database_constants.h`. 
- You can use `clangd` when reading the code. The `compile_commands.json` file will be automatically generated after cmake.
- You can install the [Better Comments](https://marketplace.visualstudio.com/items?itemName=aaron-bond.better-comments) extension to highlight the TODO or remarked comments.
- The code also runs for clang, but we use GCC unroll in some places. Please change those lines if you want to test optimal throughput.
