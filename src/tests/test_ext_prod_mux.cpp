#include "tests.h"
#include "rlwe.h"

void PirTest::test_ext_prod_mux() {
  print_func_name(__FUNCTION__);
  PirParams pir_params;
  PirServer server(pir_params);
  PirClient client(pir_params);
  const size_t coeff_count = DBConsts::PolyDegree;

  // create two ciphertexts
  std::vector<uint64_t> a(coeff_count), b(coeff_count);
  a[0] = 508; a[1] = 509; a[2] = 510;
  b[0] = 511; b[1] = 512; b[2] = 513;

  const uint64_t q = pir_params.get_coeff_modulus()[0];
  const uint64_t t = pir_params.get_plain_mod();
  const double sigma = pir_params.get_noise_std_dev();

  RlweSk rlwe_sk;
  rlwe_sk.data.assign(client.secret_key_.data().data(),
                      client.secret_key_.data().data() + coeff_count);
  std::mt19937_64 rng(std::random_device{}());

  RlweCt a_encrypted, b_encrypted;
  encrypt_bfv(a, rlwe_sk, coeff_count, q, t, sigma, rng, a_encrypted);
  encrypt_bfv(b, rlwe_sk, coeff_count, q, t, sigma, rng, b_encrypted);

  // create a GSW ciphertext of 1
  const size_t gsw_l = pir_params.get_l();
  const size_t base_log2 = pir_params.get_base_log2();
  GSWEval data_gsw(pir_params, gsw_l, base_log2);
  std::vector<uint64_t> one(coeff_count);
  std::vector<uint64_t> zero(coeff_count);
  one[0] = 1;
  GSWCt one_gsw  = data_gsw.plain_to_gsw(one,  rlwe_sk, rng);
  GSWCt zero_gsw = data_gsw.plain_to_gsw(zero, rlwe_sk, rng);

  // test the mux
  RlweCt result;
  result.resize(coeff_count);
  RlwePt result_pt;
  server.ext_prod_mux(a_encrypted, b_encrypted, one_gsw, result);
  {
    decrypt(result, rlwe_sk, coeff_count, q, t, result_pt);
    BENCH_PRINT("Mux result: " << result_pt.data[0] << " " << result_pt.data[1] << " " << result_pt.data[2]);
  }

  // Re-encrypt a/b — ext_prod_mux mutates in place
  encrypt_bfv(a, rlwe_sk, coeff_count, q, t, sigma, rng, a_encrypted);
  encrypt_bfv(b, rlwe_sk, coeff_count, q, t, sigma, rng, b_encrypted);
  server.ext_prod_mux(a_encrypted, b_encrypted, zero_gsw, result);
  {
    decrypt(result, rlwe_sk, coeff_count, q, t, result_pt);
    BENCH_PRINT("Mux result: " << result_pt.data[0] << " " << result_pt.data[1] << " " << result_pt.data[2]);
  }
  PRINT_BAR;
}
