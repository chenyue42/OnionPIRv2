#include "tests.h"

void PirTest::test_decrypt_mod_q() {
  // this is testing if custom decryption works for the original modulus. (no modulus switching involved)
  // ! Use Small parameters for this test
  print_func_name(__FUNCTION__);
  PirParams pir_params;
  PirClient client(pir_params);
  const auto params = pir_params.get_seal_params();
  auto context_ = seal::SEALContext(params);
  auto secret_key_ = client.secret_key_;
  auto evaluator_ = seal::Evaluator(context_);
  auto encryptor_ = seal::Encryptor(context_, secret_key_);

  const size_t coeff_count = DBConsts::PolyDegree;

  // the test data vector a and results are both in BFV scheme.
  seal::Plaintext a(coeff_count), result;
  a[0] = 1; a[1] = 2; a[2] = 4;
  BENCH_PRINT("Vector a: " << a.to_string());
  seal::Ciphertext a_encrypted;    // encrypted "a" will be stored here.
  encryptor_.encrypt_symmetric(a, a_encrypted);

  // Bridge seal::Ciphertext -> RlweCt for decrypt_mod_q.
  RlweCt rlwe_ct;
  rlwe_ct.c0.assign(a_encrypted.data(0), a_encrypted.data(0) + coeff_count);
  rlwe_ct.c1.assign(a_encrypted.data(1), a_encrypted.data(1) + coeff_count);
  rlwe_ct.ntt_form = a_encrypted.is_ntt_form();
  result = client.decrypt_mod_q(rlwe_ct);
  BENCH_PRINT("Decrypted result: " << result.to_string());
}
