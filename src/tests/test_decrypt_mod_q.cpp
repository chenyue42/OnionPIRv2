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
  const auto coeff_modulus = pir_params.get_coeff_modulus();
  result = client.decrypt_mod_q(a_encrypted, coeff_modulus[0].value());
  BENCH_PRINT("Decrypted result: " << result.to_string());
}
