# OnionPIR version 2

> **WARNING:** Note that this repository is for research purpose. Do not use this in production directly.

### Preliminaries

We ran our code on a `Intel(R) Xeon(R) Platinum 8358 CPU @ 2.60GHz` (Ice Lake, 32 cores per socket, AVX-512). AVX2 and AVX-512 are used to accelerate the first-dimension matrix multiply and NTT-related computation.

We use c++20 and `GCC 11.4.0` for compilation.

### Installation

OnionPIRv2 only depends on [Intel HEXL](https://github.com/intel/hexl) for fast NTT. The expected install path is set in the top-level `CMakeLists.txt` (`HEXL_DIR`) — adjust it to match your environment, or pass `-DHEXL_DIR=...` on the cmake line. Pass `-DUSE_HEXL=OFF` to build without HEXL (scalar fallback).

```
python3 run.py            # build (Benchmark) + run pir test on k1_comp
python3 run.py --build-only
```

### Usage

`run.py` handles building with the correct compile flags and running the binary.

```
python run.py [options]
```

| Option | Description |
|---|---|
| `-c NAME`, `--config NAME` | Build configuration (default: `k1_comp`). See available configs below |
| `-v`, `--verbose` | Build in Debug mode (enables `DEBUG_PRINT` at compile time) |
| `--no-compress` | Run PIR without query compression/decompression |
| `-t NAME`, `--test NAME` | Test to run (default: `pir`). See available tests below |
| `-n N`, `--experiments N` | Number of experiment iterations (default: 5) |
| `-w N`, `--warmup N` | Number of warmup iterations (default: 3) |
| `-o FILE`, `--output FILE` | Write results to file (bare name goes to `outputs/`) |
| `-j N`, `--jobs N` | Parallel make jobs (default: all cores) |
| `--build-only` | Build without running |
| `-h`, `--help` | Show help message |

**Examples:**

```bash
# Default: k1_comp config, pir test, 5 trials + 3 warmup
python3 run.py

# Pick a different config
python3 run.py -c k1
python3 run.py -c k2_mp
python3 run.py -c n4096_k2_mp

# Verbose/debug mode — recompiles with DEBUG_PRINT enabled
python3 run.py -v

# Save results to outputs/results.txt
python3 run.py -o results.txt

# Just build, don't run
python3 run.py --build-only

# Run a specific test
python3 run.py -t fst_dim
```

**Available configs:** `k1`, `k1_comp` (default, composite-mod K=1), `k2_mp`, `n4096_k2_mp`. See `src/includes/database_constants.h` for per-config parameters.

**Available tests:** `pir` (default), `bfv`, `ext_prod`, `ext_prod_mux`, `fst_dim`, `fast_expand`, `decrypt_mod_q`, `mod_switch`, `db_shape`, `bv_ks`, `cpu_info`, `hexl_ntt`, `utils_arith`, `noise_sampling`, `rlwe_enc`, `barrett`, `plan_params`

You can also build and run manually with CMake:

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Benchmark -DACTIVE_CONFIG=CONFIG_N2048_K1_COMP
make && ./Onion-PIR --test pir
```



### Tips

- Currently, most of the parameters can be adjusted in `src/includes/database_constants.h`. 
- You can use `clangd` when reading the code. The `compile_commands.json` file will be automatically generated after cmake.
- You can install the [Better Comments](https://marketplace.visualstudio.com/items?itemName=aaron-bond.better-comments) extension to highlight the TODO or remarked comments.
- The code also runs for clang, but we use GCC unroll in some places. Please change those lines if you want to test optimal throughput.
