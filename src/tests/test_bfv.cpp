#include "tests.h"

// This is an example of how to use the BFV scheme in SEAL and in our PIR scheme.
void PirTest::bfv_example() {
  print_func_name(__FUNCTION__);
  // You need a a chunk of code to init the seal parameters. Here is the minimum you need:
  static seal::EncryptionParameters params(seal::scheme_type::bfv);
  const size_t coeff_count = 4096;  // you can try other powers of two.
  params.set_poly_modulus_degree(coeff_count); // example: a_1 x^4095 + a_2 x^4094 + ...
  const uint64_t pt_mod = utils::generate_prime(49); // 49 bits for the plain modulus, then you can use 48 bits for storing data.
  params.set_plain_modulus(pt_mod);
  std::vector<int> bit_sizes({60, 60,60}); // You can also try our own DBConsts::CoeffMods
  const auto coeff_modulus = CoeffModulus::Create(coeff_count, bit_sizes);
  params.set_coeff_modulus(coeff_modulus);
  // ================== END OF SEAL PARAMS INIT ==================
  // The following are things you need to encrypt, evaluate, and decrypt BFV.
  SEALContext context_(params);
  auto evaluator_ = seal::Evaluator(context_);
  auto keygen_ = seal::KeyGenerator(context_);
  auto secret_key_ = keygen_.secret_key();
  auto encryptor_ = seal::Encryptor(context_, secret_key_);

  static auto decryptor_ = seal::Decryptor(context_, secret_key_);
  // =============================================================
  BENCH_PRINT("coeff_count: " << coeff_count);
  BENCH_PRINT("Num of coeff mods that SEAL uses: "
              << context_.key_context_data()->parms().coeff_modulus().size());
  BENCH_PRINT("Num of coeff mods used for actual ciphertexts"
              << context_.first_context_data()->parms().coeff_modulus().size());

  // ============= Now let's try some BFV * BFV multiplication in coefficient form ==============
  seal::Plaintext a(coeff_count), b(coeff_count), result;
  a[0] = 1; a[1] = 9;
  b[0] = 3; b[1] = 6;
  BENCH_PRINT("Plaintext a: " << a.to_string());
  BENCH_PRINT("Plaintext b: " << b.to_string());

  seal::Ciphertext a_encrypted, b_encrypted, cipher_result;
  encryptor_.encrypt_symmetric(a, a_encrypted);
  encryptor_.encrypt_symmetric(b, b_encrypted);

  BENCH_PRINT("Noise budget before: " << decryptor_.invariant_noise_budget(a_encrypted));
  evaluator_.multiply(a_encrypted, b_encrypted, cipher_result);
  decryptor_.decrypt(cipher_result, result);
  // You can see that this direct multiplication consumes a lot of noise budget.
  BENCH_PRINT("Noise budget after: " << decryptor_.invariant_noise_budget(cipher_result));
  BENCH_PRINT("BFV x BFV result: " << result.to_string());
  PRINT_BAR;
  // ============= Now let's try addition in coefficient form ==============
  a.set_zero(); b.set_zero();
  a[0] = 1; a[1] = 9;
  b[0] = 3; b[1] = 6;
  BENCH_PRINT("Vector a: " << a.to_string());
  BENCH_PRINT("Vector b: " << b.to_string());

  encryptor_.encrypt_symmetric(a, a_encrypted);
  encryptor_.encrypt_symmetric(b, b_encrypted);
  BENCH_PRINT("Noise budget before: " << decryptor_.invariant_noise_budget(a_encrypted));
  evaluator_.add(a_encrypted, b_encrypted, cipher_result);
  decryptor_.decrypt(cipher_result, result);
  BENCH_PRINT("Noise budget after: " << decryptor_.invariant_noise_budget(cipher_result));
  BENCH_PRINT("BFV + BFV result: " << result.to_string());
  PRINT_BAR;

  // ============= Now let's try addition and multiplication in ntt form ==============
  a.set_zero(); b.set_zero();
  a[0] = 1; a[1] = 9;
  b[0] = 3; b[1] = 6;
  BENCH_PRINT("Vector a: " << a.to_string());
  BENCH_PRINT("Vector b: " << b.to_string());
  encryptor_.encrypt_symmetric(a, a_encrypted);
  encryptor_.encrypt_symmetric(b, b_encrypted);
  BENCH_PRINT("Noise budget before: " << decryptor_.invariant_noise_budget(a_encrypted));

  evaluator_.transform_to_ntt_inplace(a_encrypted);
  evaluator_.transform_to_ntt_inplace(b_encrypted);
  evaluator_.add(a_encrypted, b_encrypted, cipher_result);
  evaluator_.transform_from_ntt_inplace(cipher_result);

  decryptor_.decrypt(cipher_result, result);
  BENCH_PRINT("Noise budget after: " << decryptor_.invariant_noise_budget(cipher_result)); // noise budget is almost the same.
  BENCH_PRINT("NTT + NTT result: " << result.to_string());  // and the result is correct! NTT form polynomial is additive
  PRINT_BAR;

  // ============= Now let's try BFV multiplied by a constant in ntt form ==============
  seal::Plaintext scalar(coeff_count);
  // scalar[0] = 2;
  // scalar[1] = 3;

  scalar[0] = 1ul << 46;
  scalar[1] = 1ul << 46;
  scalar[3] = 1ul << 46;
  BENCH_PRINT("Vector a: " << a.to_string());
  BENCH_PRINT("Scalar: " << scalar.to_string());
  evaluator_.transform_from_ntt_inplace(a_encrypted);
  BENCH_PRINT("Noise budget before: " << decryptor_.invariant_noise_budget(a_encrypted));
  evaluator_.transform_to_ntt_inplace(a_encrypted);
  evaluator_.transform_to_ntt_inplace(scalar, context_.first_parms_id()); // This happens in preprocess_ntt
  // Now instead of using multiply_plain, I want to demonstrate what happens in the first dimension evaluation.
  // This is demonstrating what you can do in ntt form, but the actual order of computation in OnionPIRv2 fst dim can be different.
  size_t rns_mod_cnt = coeff_modulus.size() - 1;
  std::vector<uint128_t> res(coeff_count * rns_mod_cnt * 2);
  std::fill(res.begin(), res.end(), 0);
  uint64_t *ct0_ptr = a_encrypted.data(0);
  uint64_t *ct1_ptr = a_encrypted.data(1);
  uint128_t *res0_ptr = res.data();
  uint128_t *res1_ptr = res.data() + coeff_count * rns_mod_cnt;
  uint64_t *pt_ptr = scalar.data();
  // element wise vector multiplication.
  for (size_t i = 0; i < coeff_count * rns_mod_cnt; i++) {
    res0_ptr[i] = static_cast<uint128_t>(ct0_ptr[i]) * pt_ptr[i];
    res1_ptr[i] = static_cast<uint128_t>(ct1_ptr[i]) * pt_ptr[i];
  }
  // Another scan on the res to reduce the modulus.
  // Meanwhile we can reconstruct the ciphertext from the res vector and decrypt it.
  seal::Ciphertext scalar_mul_result = a_encrypted; // just copy a random ciphertext with correct format, we will overwrite it.
  uint64_t *scal_mul_ct0_ptr = scalar_mul_result.data(0);
  uint64_t *scal_mul_ct1_ptr = scalar_mul_result.data(1);
  for (size_t i = 0; i < coeff_count; i++) {
    for (size_t j = 0; j < rns_mod_cnt; j++) {
      auto curr_mod = coeff_modulus[j].value();
      scal_mul_ct0_ptr[i + j * coeff_count] = res0_ptr[i + j * coeff_count] % curr_mod;
      scal_mul_ct1_ptr[i + j * coeff_count] = res1_ptr[i + j * coeff_count] % curr_mod;
    }
  }
  evaluator_.transform_from_ntt_inplace(scalar_mul_result);
  decryptor_.decrypt(scalar_mul_result, result);
  BENCH_PRINT("NTT x scalar result: " << result.to_string());  // and the result is correct! NTT form polynomial is multiplicative
  BENCH_PRINT("Noise budget after: " << decryptor_.invariant_noise_budget(scalar_mul_result)); // noise budget is almost the same.
  /*
  Now, in the old OnionPIR, this kind of elementwise multiplication is computed for num_poly many times. That is, the smallest operation
  is this vector-vector elementwise multiplication. However, this is bad for cache. We have further comparison in matrix.h
  */
  PRINT_BAR;

  // ============= Now let's try BFV multiplied by two identical constants then subtract ==============
  // Actually, this creates something called transparant ciphertext, which is warned in the SEAL documentation.
  seal::Plaintext constant(coeff_count);
  constant[0] = 2;
  BENCH_PRINT("If you see an error about 'transparent ciphertext' below, please make sure you are using -DSEAL_THROW_ON_TRANSPARENT_CIPHERTEXT=OFF when building SEAL");
  evaluator_.transform_from_ntt_inplace(a_encrypted);
  seal::Ciphertext left, right;
  evaluator_.multiply_plain(a_encrypted, constant, left);
  evaluator_.add(a_encrypted, a_encrypted, right);
  evaluator_.sub_inplace(left, right);
  decryptor_.decrypt(left, result);
  BENCH_PRINT("You should see a zero ¬_¬: " << result.to_string());
}
