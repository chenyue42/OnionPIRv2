#pragma once
#include "pir.h"
#include "seal/seal.h"
#include <iostream>
#include <fstream>


#ifdef _DEBUG
#define PRINT_INT_ARRAY(arr_name, arr, size) \
    do {                                     \
        std::cout << arr_name << ": [";      \
        for (size_t i = 0; i < size; ++i) {     \
            std::cout << arr[i];             \
            if (i < size - 1)                \
                std::cout << ", ";           \
        }                                    \
        std::cout << "]" << std::endl;       \
    } while (0)
#endif

#ifdef _BENCHMARK
#define PRINT_INT_ARRAY(arr_name, arr, size) ;  // do nothing
#endif



inline void print_func_name(std::string func_name) {
  PRINT_BAR;
  #ifdef _DEBUG
    std::cout << "                    "<< func_name << "(Debug build)" << std::endl;
  #endif
  #ifdef _BENCHMARK
    std::cout << "                    "<< func_name << "(Benchmark build)" << std::endl;
  #endif
  PRINT_BAR;
}

template <typename T> std::string to_string(T x) {
  std::string ret;
  if (x == 0) {
    return "0";
  }
  while (x) {
    ret += (x % 10) + '0';
    x /= 10;
  }
  reverse(ret.begin(), ret.end());
  return ret;
}

namespace utils {

// void shift_polynomial(const seal::EncryptionParameters &params,
//                       const seal::Ciphertext &src, seal::Ciphertext &dst,std::int64_t k);

void negacyclic_shift_poly_coeffmod(seal::util::ConstCoeffIter poly,
                                    size_t coeff_count, size_t shift,
                                    const seal::Modulus &modulus,
                                    seal::util::CoeffIter result);
void shift_polynomial(seal::EncryptionParameters &params,
                      seal::Ciphertext &encrypted,
                      seal::Ciphertext &destination, size_t index);

// Convert a 128-bit unsigned integer to a string
std::string uint128_to_string(uint128_t value);

/**
 * @brief Construct a RGSW gadget. Notice that the gadget is from large to
 * small, i.e., the first row is B^(log q / log B -1), the final row is 1.
 */
std::vector<std::vector<uint64_t>>
gsw_gadget(size_t l, uint64_t base_log2, size_t rns_mod_cnt,
           const std::vector<seal::Modulus> &coeff_modulus);

// Generate a prime that is bit_width long
std::uint64_t generate_prime(size_t bit_width);

// New functions for plaintext handling
void print_plaintext(const seal::Plaintext &plaintext, size_t count = 10);

bool plaintext_is_equal(const seal::Plaintext &plaintext1, const seal::Plaintext &plaintext2);

void print_progress(size_t current, size_t total);

size_t next_pow_of_2(const size_t n);

size_t roundup_div(const size_t numerator, const size_t denominator);

void fill_rand_arr(uint64_t *arr, size_t size);

// given a number x and a logn, return the bit-reversed number of x
inline size_t bit_reverse(size_t x, size_t logn) {
  size_t n = 1 << logn;
  size_t y = 0;
  for (size_t i = 0; i < logn; i++) {
    y = (y << 1) | (x & 1);
    x >>= 1;
  }
  return y;
  }

  // compute ceil(x/2^k). equivalent to ceil^k(x/2).
  inline size_t repeated_ceil_half(size_t x, size_t k) {
    size_t divisor = 1 << k;
    return (x + divisor - 1) / divisor;
  }


} // namespace utils