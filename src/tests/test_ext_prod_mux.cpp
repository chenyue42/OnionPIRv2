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
  seal::Ciphertext a_seal, b_seal;
  client.encryptor_.encrypt_symmetric(a, a_seal);
  client.encryptor_.encrypt_symmetric(b, b_seal);

  // Bridge seal::Ciphertext -> RlweCt (single-mod)
  auto to_rlwe = [&](const seal::Ciphertext &src) {
    RlweCt r;
    r.c0.assign(src.data(0), src.data(0) + coeff_count);
    r.c1.assign(src.data(1), src.data(1) + coeff_count);
    r.ntt_form = src.is_ntt_form();
    return r;
  };
  auto to_seal = [&](const RlweCt &src) {
    seal::Ciphertext r(pir_params.get_context());
    r.resize(pir_params.get_context(), 2);
    std::copy(src.c0.begin(), src.c0.begin() + coeff_count, r.data(0));
    std::copy(src.c1.begin(), src.c1.begin() + coeff_count, r.data(1));
    r.is_ntt_form() = src.ntt_form;
    return r;
  };
  RlweCt a_encrypted = to_rlwe(a_seal);
  RlweCt b_encrypted = to_rlwe(b_seal);

  // create a GSW ciphertext of 1
  const size_t gsw_l = pir_params.get_l();
  const size_t base_log2 = pir_params.get_base_log2();
  GSWEval data_gsw(pir_params, gsw_l, base_log2);
  std::vector<uint64_t> one(coeff_count);
  std::vector<uint64_t> zero(coeff_count);
  one[0] = 1;
  zero[0] = 0;
  RlweSk rlwe_sk;
  rlwe_sk.data.assign(client.secret_key_.data().data(),
                      client.secret_key_.data().data() + coeff_count);
  std::mt19937_64 rng(std::random_device{}());
  GSWCiphertext one_gsw  = data_gsw.plain_to_gsw(one,  rlwe_sk, rng);
  GSWCiphertext zero_gsw = data_gsw.plain_to_gsw(zero, rlwe_sk, rng);

  // test the mux
  RlweCt result;
  result.resize(coeff_count);
  seal::Plaintext result_pt;
  server.ext_prod_mux(a_encrypted, b_encrypted, one_gsw, result);
  {
    seal::Ciphertext tmp = to_seal(result);
    client.decryptor_.decrypt(tmp, result_pt);
    BENCH_PRINT("Mux result: " << result_pt.to_string());
  }

  // Re-bridge a/b — ext_prod_mux mutates in place
  a_encrypted = to_rlwe(a_seal);
  b_encrypted = to_rlwe(b_seal);
  server.ext_prod_mux(a_encrypted, b_encrypted, zero_gsw, result);
  {
    seal::Ciphertext tmp = to_seal(result);
    client.decryptor_.decrypt(tmp, result_pt);
    BENCH_PRINT("Mux result: " << result_pt.to_string());
  }
  PRINT_BAR;
}
