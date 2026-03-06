#include "tests.h"

void PirTest::test_sk_mod_switch() {
  print_func_name(__FUNCTION__);
  // Create two sets of parameters, one with {60, 60}, one with {30, 60} mods
  PirParams pir_params;
  seal::EncryptionParameters params1(seal::scheme_type::bfv);  // or use this for explicit setup.
  seal::EncryptionParameters params2(seal::scheme_type::bfv);
  const size_t coeff_count = 2048;  // you can try other powers of two.
  params1.set_poly_modulus_degree(coeff_count);
  params2.set_poly_modulus_degree(coeff_count);
  const uint64_t pt_mod = utils::generate_prime(17); // 49 bits for the plain modulus, then you can use 48 bits for storing data.
  params1.set_plain_modulus(pt_mod);
  params2.set_plain_modulus(pt_mod);
  std::vector<int> bit_sizes1({60,60}); // set this same as DBConsts::CoeffMods
  std::vector<int> bit_sizes2({30,60});

  const auto coeff_modulus1 = CoeffModulus::Create(coeff_count, bit_sizes1);
  const auto coeff_modulus2 = CoeffModulus::Create(coeff_count, bit_sizes2);
  params1.set_coeff_modulus(coeff_modulus1);
  params2.set_coeff_modulus(coeff_modulus2);

  // we showed an explicit way to setup the parameters above. But since we need
  // the client secret key for this test, we need to use the PirParams to setup our client.
  params1 = pir_params.get_seal_params();
  PirClient client(pir_params);

  // ==================== Create SEALContext objects
  auto context1 = seal::SEALContext(params1);
  auto context2 = seal::SEALContext(params2);
  auto context_data1 = context1.key_context_data();
  auto context_data2 = context2.key_context_data();

  for (size_t i = 0; i < coeff_modulus1.size(); i++) {
    BENCH_PRINT("Big modulus " << i << ": " << coeff_modulus1[i].value());
  }
  for (size_t i = 0; i < coeff_modulus2.size(); i++) {
    BENCH_PRINT("Small modulus " << i << ": " << coeff_modulus2[i].value());
  }

  // ==================== Create evaluator, secret key, encryptor of the large setting
  auto evaluator1 = seal::Evaluator(context1);
  auto keygen1 = seal::KeyGenerator(context1);
  auto sk1 = keygen1.secret_key();
  auto encryptor1 = seal::Encryptor(context1, sk1);
  auto decryptor1 = seal::Decryptor(context1, sk1);

  // test if the encryption and decryption works
  seal::Plaintext pt1(coeff_count), result1;
  pt1[0] = 1; pt1[1] = 2;
  BENCH_PRINT("Plaintext: " << pt1.to_string());
  seal::Ciphertext ct1;
  encryptor1.encrypt_symmetric(pt1, ct1);
  decryptor1.decrypt(ct1, result1);
  BENCH_PRINT("Decrypted result: " << result1.to_string());
  BENCH_PRINT("--------------------------------------------------------------------------")


  // ==================== Create evaluator, secret key, encryptor of the small setting
  // Now, we create a new secret key with the same logical data as sk1, but represented in new modulus.
  seal::SecretKey sk2 = client.sk_mod_switch(sk1, params2);

  // And this new secret key can be used to encrypt and decrypt normally as if we use a new keygen.
  auto encryptor2 = seal::Encryptor(context2, sk2);
  auto decryptor2 = seal::Decryptor(context2, sk2);
  // test if the encryption and decryption works
  seal::Plaintext pt2(coeff_count), result2;
  pt2[0] = 1; pt2[1] = 2;
  BENCH_PRINT("Plaintext: " << pt2.to_string());
  seal::Ciphertext ct2;
  encryptor2.encrypt_symmetric(pt2, ct2);
  decryptor2.decrypt(ct2, result2);
  BENCH_PRINT("Decrypted result: " << result2.to_string());
}
