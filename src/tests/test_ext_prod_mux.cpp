#include "tests.h"

void PirTest::test_ext_prod_mux() {
  print_func_name(__FUNCTION__);
  PirParams pir_params;
  PirServer server(pir_params);
  PirClient client(pir_params);
  const size_t coeff_count = DBConsts::PolyDegree;

  // create two ciphertexts
  seal::Plaintext a(coeff_count), b(coeff_count);
  a[0] = 508; a[1] = 509; a[2] = 510;
  b[0] = 511; b[1] = 512; b[2] = 513;
  seal::Ciphertext a_encrypted, b_encrypted;
  client.encryptor_.encrypt_symmetric(a, a_encrypted);
  client.encryptor_.encrypt_symmetric(b, b_encrypted);

  // create a GSW ciphertext of 1
  const size_t gsw_l = pir_params.get_l();
  const size_t base_log2 = pir_params.get_base_log2();
  GSWEval data_gsw(pir_params, gsw_l, base_log2);
  std::vector<uint64_t> one(coeff_count);
  std::vector<uint64_t> zero(coeff_count);
  one[0] = 1;
  zero[0] = 0;
  GSWCiphertext one_gsw = data_gsw.plain_to_gsw(one, client.encryptor_, client.secret_key_);
  GSWCiphertext zero_gsw = data_gsw.plain_to_gsw(zero, client.encryptor_, client.secret_key_);

  // test the mux
  seal::Ciphertext result;
  seal::Plaintext result_pt;
  server.ext_prod_mux(a_encrypted, b_encrypted, one_gsw, result);
  client.decryptor_.decrypt(result, result_pt);
  BENCH_PRINT("Mux result: " << result_pt.to_string());

  server.ext_prod_mux(a_encrypted, b_encrypted, zero_gsw, result);
  client.decryptor_.decrypt(result, result_pt);
  BENCH_PRINT("Mux result: " << result_pt.to_string());
  PRINT_BAR;
}
