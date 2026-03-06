#include "tests.h"

void PirTest::test_raw_pt_ct_mult() {
  // what is the speed of doing polynomial multiplication in coefficient form?
  print_func_name(__FUNCTION__);
  CLEAN_TIMER();
  PirParams pir_params;
  // You need a a chunk of code to init the seal parameters. Here is the minimum you need:
  seal::EncryptionParameters params(seal::scheme_type::bfv);
  const size_t coeff_count = 2048;  // you can try other powers of two.
  params.set_poly_modulus_degree(coeff_count); // example: a_1 x^4095 + a_2 x^4094 + ...
  const uint64_t pt_mod = utils::generate_prime(17); // 49 bits for the plain modulus, then you can use 48 bits for storing data.
  params.set_plain_modulus(pt_mod);
  std::vector<int> bit_sizes({60,60}); // You can also try our own DBConsts::CoeffMods
  const auto coeff_modulus = CoeffModulus::Create(coeff_count, bit_sizes);
  params.set_coeff_modulus(coeff_modulus);
  const size_t bits_per_coeff = params.plain_modulus().bit_count() - 1;
  const uint64_t coeff_mask = (uint64_t(1) << (bits_per_coeff)) - 1;
  const size_t num_pt = pir_params.get_num_pt();
  // ================== END OF SEAL PARAMS INIT ==================
  // The following are things you need to encrypt, evaluate, and decrypt BFV.
  SEALContext context_(params);
  auto evaluator_ = seal::Evaluator(context_);
  auto keygen_ = seal::KeyGenerator(context_);
  auto secret_key_ = keygen_.secret_key();
  auto encryptor_ = seal::Encryptor(context_, secret_key_);
  auto decryptor_ = seal::Decryptor(context_, secret_key_);
  // ============= Generate the plaintexts ==============
  seal::Plaintext pt1(coeff_count), pt2(coeff_count), pt_ntt;
  uint64_t* pt1_data = pt1.data();
  uint64_t* pt2_data = pt2.data();
  // Generate two random plaintexts
  utils::fill_rand_arr(pt1_data, coeff_count);
  utils::fill_rand_arr(pt2_data, coeff_count);
  for (size_t i = 0; i < coeff_count; i++) {
    pt1_data[i] &= coeff_mask;
    pt2_data[i] &= coeff_mask;
  }
  pt_ntt = pt1;
  evaluator_.transform_to_ntt_inplace(pt_ntt, context_.first_parms_id());

  const size_t iter_num = num_pt;
  BENCH_PRINT("iter_num: " << iter_num);
  seal::Ciphertext ct1, ct2;
  encryptor_.encrypt_symmetric(pt1, ct1);
  encryptor_.encrypt_symmetric(pt2, ct2);
  evaluator_.transform_to_ntt_inplace(ct2); // only ct2 is in NTT form.
  // ============= Perform the multiplication ==============
  TIME_START("naive ct * naive pt");
  for (size_t i = 0; i < iter_num; i++) {
    evaluator_.multiply_plain_inplace(ct1, pt1);
  }
  TIME_END("naive ct * naive pt");

  TIME_START("ntt ct * pt");
  for (size_t i = 0; i < iter_num; i++) {
    evaluator_.multiply_plain_inplace(ct2, pt1);
  }
  TIME_END("ntt ct * pt");

  TIME_START("ntt ct * ntt pt");
  for (size_t i = 0; i < iter_num; i++) {
    evaluator_.multiply_plain_inplace(ct2, pt_ntt);
  }
  TIME_END("ntt ct * ntt pt");
  // ============= Decrypt and print the result ==============
  evaluator_.transform_from_ntt_inplace(ct2);
  seal::Plaintext res_pt;
  decryptor_.decrypt(ct2, res_pt);
  BENCH_PRINT("Result: " << res_pt.to_string().substr(0, 50));
  // ============= Profiling the multiplication ==============
  END_EXPERIMENT();
  PRINT_RESULTS();
  double tot = GET_LAST_TIME("ntt ct * pt");
  double amortized = tot / iter_num;
  BENCH_PRINT("ntt ct * pt: " << amortized << " ms");
}
