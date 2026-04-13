#include "tests.h"

void PirTest::serialization_example() {
  print_func_name(__FUNCTION__);
  PirParams pir_params;
  auto params = pir_params.get_seal_params();
  auto context_ = seal::SEALContext(params);
  auto evaluator_ = seal::Evaluator(context_);
  auto keygen_ = seal::KeyGenerator(context_);
  auto secret_key_ = keygen_.secret_key();
  auto encryptor_ = seal::Encryptor(context_, secret_key_);
  auto decryptor_ = seal::Decryptor(context_, secret_key_);

  std::stringstream data_stream;

  // ================== Raw Zero ciphertext ==================
  seal::Ciphertext raw_zero;
  encryptor_.encrypt_zero_symmetric(raw_zero);
  auto raw_size = raw_zero.save(data_stream); // store the raw zero in the stream
// ================== SEAL original method for creating serialized zero ==================
  // Original method for creating a serializable object
  Serializable<Ciphertext> orig_serialized_zero = encryptor_.encrypt_zero_symmetric();
  auto s_size = orig_serialized_zero.save(data_stream);   // ! Storing the original zero

  // ================== New way to create a ciphertext with a seed ==================
  // New way to create a ciphertext with a seed, do some operations and then convert it to a serializable object.
  seal::Ciphertext new_seeded_zero;
  encryptor_.encrypt_zero_symmetric_seeded(new_seeded_zero); // This function allows us to change the ciphertext.data(0).

  // Add something in the third coeeficient of seeded_zero
  DEBUG_PRINT("Size: " << new_seeded_zero.size());
  auto ptr_0 = new_seeded_zero.data(0);
  auto ptr_1 = new_seeded_zero.data(1); // corresponds to the second polynomial (c_1)
  // print the binary value of the first coefficient
  BENCH_PRINT("Indicator:\t" << std::bitset<64>(ptr_1[0]));  // used in has_seed_marker()
  // the seed is stored in here. By the time I write this code, it takes 81
  // bytes to store the prng seed. Notice that they have common prefix.
  BENCH_PRINT("Seed: \t\t" << std::bitset<64>(ptr_1[1]));
  BENCH_PRINT("Seed: \t\t" << std::bitset<64>(ptr_1[2]));
  BENCH_PRINT("Seed: \t\t" << std::bitset<64>(ptr_1[3]));
  BENCH_PRINT("Seed: \t\t" << std::bitset<64>(ptr_1[4]));
  BENCH_PRINT("Seed: \t\t" << std::bitset<64>(ptr_1[5]));

  auto mods = pir_params.get_coeff_modulus();
  auto plain_modulus = pir_params.get_plain_mod();
  uint128_t ct_mod = 1;
  for (size_t mod_id = 0; mod_id < mods.size(); mod_id++) {
    ct_mod *= mods[mod_id];
  }
  uint128_t delta = ct_mod / plain_modulus;  // delta = floor (ciphertext modulus / plaintext modulus)
  uint128_t message = 15;
  uint128_t to_add = delta * message;
  auto padding = params.poly_modulus_degree();
  for (size_t mod_id = 0; mod_id < mods.size(); mod_id++) {
    ptr_0[mod_id * padding] = (ptr_0[mod_id * padding] + (to_add % mods[mod_id])) % mods[mod_id];
  }

  // write the serializable object to the stream
  auto s2_size = new_seeded_zero.save(data_stream); // Storing new ciphertext with a seed

  BENCH_PRINT("Size of the ciphertexts: " << new_seeded_zero.size());

  // ================== Deserialize and decrypt the ciphertexts ==================
  seal::Ciphertext raw_ct, orig_ct, new_ct;
  raw_ct.load(context_, data_stream);  // loading the raw zero
  orig_ct.load(context_, data_stream);  // loading the original zero
  new_ct.load(context_, data_stream); // loading the new ciphertext with a seed

  // decrypt the ciphertexts
  seal::Plaintext raw_pt, orig_pt, new_pt;
  decryptor_.decrypt(raw_ct, raw_pt);
  decryptor_.decrypt(orig_ct, orig_pt);
  decryptor_.decrypt(new_ct, new_pt);

  // ================== Print the results ==================
  BENCH_PRINT("Raw zero size: " << raw_size);
  BENCH_PRINT("Serializable size 1: " << s_size);
  BENCH_PRINT("Serializable size 2: " << s2_size); // smaller size, but allow us to work on the ciphertext!

  BENCH_PRINT("Raw plaintext: " << raw_pt.to_string());
  BENCH_PRINT("Original plaintext: " << orig_pt.to_string());
  BENCH_PRINT("New plaintext: " << new_pt.to_string()); // Hopefully, this decrypts to the message.
}
