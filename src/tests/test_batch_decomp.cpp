#include "tests.h"

void PirTest::test_batch_decomp() {
  // I observed that we do external product for each polynomial in the selected
  // database after first dimension multiplication.
  // Then, I wonder if it is possible to batch the external product.
  // ! here, batch means vectorized operations. Essentially:
  // We can first do the vectorized BFV homomorphic subtraction,
  // then we decompose all the ciphertext (which generates $l$ times more ciphertexts)
  // then then the external product matrix multiplication,
  // then the delayed modulus reduction.
  // then the vectorized BFV homomorphic addition.
  // ? If we batch everything, can we save some time?

  // Well, I use thi test to test the batched CRT and NTT operations.
  // They are the most time-consuming operations in the external product.
  print_func_name(__FUNCTION__);
  CLEAN_TIMER();

  PirParams pir_params;
  const size_t other_dim_sz = pir_params.get_other_dim_sz();
  const auto params = pir_params.get_seal_params();
  auto context_ = seal::SEALContext(params);
  auto context_data = context_.first_context_data();
  auto evaluator_ = seal::Evaluator(context_);
  auto keygen_ = seal::KeyGenerator(context_);
  auto secret_key_ = keygen_.secret_key();
  auto encryptor_ = seal::Encryptor(context_, secret_key_);
  auto decryptor_ = seal::Decryptor(context_, secret_key_);
  auto ntt_tables = context_data->small_ntt_tables();
  seal::util::RNSBase *rns_base = context_data->rns_tool()->base_q();
  const size_t coeff_count = DBConsts::PolyDegree;
  auto pool = seal::MemoryManager::GetPool();


  // create other_dim_sz many ciphertexts with zero plaintext
  std::vector<seal::Ciphertext> ct_vec(other_dim_sz);
  for (size_t i = 0; i < other_dim_sz; i++) {
    seal::Ciphertext ct;
    encryptor_.encrypt_zero_symmetric(ct);
    ct_vec[i] = ct;
  }

  TIME_START("Batch compose");
  for (size_t i = 0; i < other_dim_sz; i++) {
    for (size_t poly_id = 0; poly_id < ct_vec[i].size(); poly_id++) {
      auto ct_ptr = ct_vec[i].data(poly_id);
      rns_base->compose_array(ct_ptr, coeff_count, pool);
    }
  }
  TIME_END("Batch compose");

  // decompose
  TIME_START("Batch decompose");
  for (size_t i = 0; i < other_dim_sz; i++) {
    for (size_t poly_id = 0; poly_id < ct_vec[i].size(); poly_id++) {
      for (size_t p = 0; p < pir_params.get_l(); p++) {
        auto ct_ptr = ct_vec[i].data(poly_id);
        rns_base->decompose_array(ct_ptr, coeff_count, pool);
      }
    }
  }
  TIME_END("Batch decompose");

  TIME_START("Batch NTT");
  for (size_t i = 0; i < other_dim_sz; i++) {
    for (size_t poly_id = 0; poly_id < ct_vec[i].size(); poly_id++) {
      for (size_t p = 0; p < pir_params.get_l(); p++) {
        auto ct_ptr = ct_vec[i].data(poly_id);
        ct_vec[i].is_ntt_form() = true;
        seal::util::ntt_negacyclic_harvey(ct_ptr, ntt_tables[0]);
        seal::util::ntt_negacyclic_harvey(ct_ptr + coeff_count, ntt_tables[1]);
      }
    }
  }
  TIME_END("Batch NTT");

  // to make sure that the optimization is not too aggressive
  size_t dummy_sum = 0;
  for (size_t i = 0; i < other_dim_sz; i++) {
    for (size_t poly_id = 0; poly_id < ct_vec[i].size(); poly_id++) {
      auto ct_ptr = ct_vec[i].data(poly_id);
      for (size_t j = 0; j < coeff_count; j++) {
        dummy_sum += ct_ptr[j];
      }
    }
  }

  // ============= Profiling the batch compose ==============
  END_EXPERIMENT();
  PRINT_RESULTS(); // uncomment this line to see the actual time elapsed in each function.

  // ! And it looks like optimized CRT and NTT saves you dozens of milliseconds. Maybe not worth it.
  // The problem is: doing many decomposition at a time requires some memory allocations.
}
