#!/usr/bin/env python3
import argparse
import subprocess
import sys
import os

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
BUILD_DIR = os.path.join(PROJECT_DIR, "build")
OUTPUT_DIR = os.path.join(PROJECT_DIR, "outputs")
BINARY = os.path.join(BUILD_DIR, "Onion-PIR")


def build(build_type: str, jobs: int):
    """Configure (if needed) and build with the given CMake build type."""
    os.makedirs(BUILD_DIR, exist_ok=True)

    # Re-configure when build type changes
    cmake_cmd = [
        "cmake",
        f"-DCMAKE_BUILD_TYPE={build_type}",
        PROJECT_DIR,
    ]
    subprocess.run(cmake_cmd, cwd=BUILD_DIR, check=True)

    make_cmd = ["make", f"-j{jobs}"]
    subprocess.run(make_cmd, cwd=BUILD_DIR, check=True)


def main():
    parser = argparse.ArgumentParser(description="Build & run OnionPIR")
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Build in Debug mode (enables DEBUG_PRINT at compile time)",
    )
    parser.add_argument(
        "--no-compress", action="store_true",
        help="Run PIR without query compression/decompression",
    )
    parser.add_argument(
        "-t", "--test", default="pir",
        help="Test to run (default: pir). Options: pir, bfv, serial, ext_prod, "
             "ext_prod_mux, fst_dim, batch_decomp, fast_expand, raw_pt_ct, "
             "decrypt_mod_q, mod_switch, sk_mod_switch, db_shape, cpu_info",
    )
    parser.add_argument(
        "-o", "--output", metavar="FILE",
        help="Write results to FILE (bare name goes to outputs/)",
    )
    parser.add_argument(
        "-j", "--jobs", type=int, default=os.cpu_count(),
        help="Parallel make jobs (default: all cores)",
    )
    parser.add_argument(
        "-n", "--experiments", type=int, default=10,
        help="Number of experiment iterations (default: 10)",
    )
    parser.add_argument(
        "-w", "--warmup", type=int, default=3,
        help="Number of warmup iterations (default: 3)",
    )
    parser.add_argument(
        "--build-only", action="store_true",
        help="Build without running",
    )
    args = parser.parse_args()

    # --- Build ---
    build_type = "Debug" if args.verbose else "Benchmark"
    build(build_type, args.jobs)

    if args.build_only:
        return

    # --- Prepare runtime args ---
    run_cmd = [BINARY, "--test", args.test,
               "--experiments", str(args.experiments),
               "--warmup", str(args.warmup)]
    if args.no_compress:
        run_cmd.append("--no-compress")

    # --- Output redirection ---
    output_file = None
    if args.output:
        path = args.output
        if "/" not in path:
            os.makedirs(OUTPUT_DIR, exist_ok=True)
            path = os.path.join(OUTPUT_DIR, path)
        else:
            os.makedirs(os.path.dirname(path), exist_ok=True)
        output_file = open(path, "w")
        print(f"Writing output to {path}")

    # --- Run ---
    try:
        subprocess.run(run_cmd, cwd=BUILD_DIR, check=True, stdout=output_file)
    finally:
        if output_file:
            output_file.close()


if __name__ == "__main__":
    main()
