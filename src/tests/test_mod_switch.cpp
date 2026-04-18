#include "tests.h"
#include "rlwe.h"

void PirTest::test_mod_switch() {
  print_func_name(__FUNCTION__);
  // ! please test with small setting (n = 2048, log q = 60, log t = 17)
  PirParams pir_params;
  PirServer server(pir_params);
  PirClient client(pir_params);
  const size_t coeff_count = DBConsts::PolyDegree;
  const uint64_t old_q = pir_params.get_coeff_modulus()[0];
  const uint64_t small_q = pir_params.get_small_q();
  const uint64_t t = pir_params.get_plain_mod();
  const double sigma = pir_params.get_noise_std_dev();
  std::mt19937_64 rng(std::random_device{}());

  std::vector<uint64_t> pt(coeff_count, 0);
  for (size_t i = 0; i < 10; ++i) {
    pt[i] = rand() % t;
  }

  BENCH_PRINT("Old q: " << old_q);
  BENCH_PRINT("New q: " << small_q);

  RlweCt rlwe_ct;
  encrypt_bfv(pt, client.rlwe_sk_, coeff_count, old_q, t, sigma, rng, rlwe_ct);
  BENCH_PRINT("Noise budget before: " << client.noise_budget(rlwe_ct));

  server.mod_switch_inplace(rlwe_ct, small_q);

  seal::Plaintext result = client.decrypt_mod_q(rlwe_ct);
  BENCH_PRINT("Client decrypted: " << result.to_string());

  // verify if ct coeffs are all less than small_q
  bool can_compress = true; // if so, then we can use 32 bits to store the coeffs.
  for (size_t i = 0; i < coeff_count; i++) {
    if (rlwe_ct.c0[i] >= small_q) {
      BENCH_PRINT("rlwe_ct.c0[" << i << "] = " << rlwe_ct.c0[i]);
      BENCH_PRINT("coeff >= small_q");
      can_compress = false;
    }
  }
  BENCH_PRINT("can_compress: " << can_compress);
}
