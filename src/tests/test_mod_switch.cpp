#include "tests.h"

void PirTest::test_mod_switch() {
  print_func_name(__FUNCTION__);
  // ! please test with small setting (n = 2048, log q = 60, log t = 17)
  PirParams pir_params;
  PirServer server(pir_params);
  PirClient client(pir_params);
  auto params = pir_params.get_seal_params();
  auto context_ = pir_params.get_context();
  auto secret_key_ = client.secret_key_;
  auto encryptor_ = seal::Encryptor(context_, secret_key_);
  auto decryptor_ = seal::Decryptor(context_, secret_key_);
  const size_t coeff_count = DBConsts::PolyDegree;

  seal::Plaintext pt(coeff_count), result(coeff_count);
  for (size_t i = 0; i < 10; ++i) {
    pt[i] = rand() % pir_params.get_plain_mod();
  }
  BENCH_PRINT("Plaintext: " << pt.to_string());

  // !temp: use log q = 60, log t = 17
  const uint64_t old_q = params.coeff_modulus()[0].value(); // old q
  const uint64_t small_q = pir_params.get_small_q(); // new q
  // const uint64_t small_q = 1073668097;
  BENCH_PRINT("Old q: " << old_q);
  BENCH_PRINT("New q: " << small_q);

  // encrypt the plaintext and apply modulus switch
  seal::Ciphertext ct;
  encryptor_.encrypt_symmetric(pt, ct);
  BENCH_PRINT("Noise budget before: " << decryptor_.invariant_noise_budget(ct));

  // Bridge seal::Ciphertext -> RlweCt for mod_switch_inplace
  RlweCt rlwe_ct;
  rlwe_ct.c0.assign(ct.data(0), ct.data(0) + coeff_count);
  rlwe_ct.c1.assign(ct.data(1), ct.data(1) + coeff_count);
  rlwe_ct.ntt_form = ct.is_ntt_form();
  server.mod_switch_inplace(rlwe_ct, small_q);

  // Bridge back for decrypt_mod_q
  seal::Ciphertext ct_small(context_);
  ct_small.resize(context_, 2);
  std::copy(rlwe_ct.c0.begin(), rlwe_ct.c0.begin() + coeff_count, ct_small.data(0));
  std::copy(rlwe_ct.c1.begin(), rlwe_ct.c1.begin() + coeff_count, ct_small.data(1));
  ct_small.is_ntt_form() = rlwe_ct.ntt_form;
  result = client.decrypt_mod_q(ct_small, small_q);
  BENCH_PRINT("Client decrypted: " << result.to_string());

  // verify if ct coeffs are all less than small_q
  bool can_compress = true; // if so, then we can use 32 bits to store the coeffs.
  for (size_t i = 0; i < coeff_count; i++) {
    if (rlwe_ct.c0[i] >= small_q) {
      BENCH_PRINT("rlwe_ct.c0[" << i << "] = " << rlwe_ct.c0[i]);
      BENCH_PRINT("coeff >= small_q");
    }
  }
  BENCH_PRINT("can_compress: " << can_compress);
}
