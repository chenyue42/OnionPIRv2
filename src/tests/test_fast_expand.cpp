#include "tests.h"

void PirTest::test_fast_expand_query() {
  print_func_name(__FUNCTION__);

  // In this test, I want to make sure if the fast_expand_query is working as expected.
  // There are two ways to order the even and odd parts of a polynomial in the expanding process.
  // One way (the normal way) is to put the even part in it's own location, and the odd part is shifted by expansion tree level size.
  // The other way (the fast way) is to put the even part in 2b and the odd part in 2b + 1.
  // Both of them expand like a binary tree, but the order of the resulting polynomial is different.
  // Here is the access pattern of the normal expansion: https://raw.githubusercontent.com/chenyue42/images-for-notes/master/uPic/expansion.png
  // And the fast expansion will look like a noremal binary tree.


  PirParams pir_params;
  auto params = pir_params.get_seal_params();
  auto context_ = pir_params.get_context();
  auto evaluator_ = seal::Evaluator(context_);
  auto keygen_ = seal::KeyGenerator(context_);
  auto secret_key_ = keygen_.secret_key();
  auto encryptor_ = seal::Encryptor(context_, secret_key_);
  auto decryptor_ = seal::Decryptor(context_, secret_key_);
  const size_t coeff_count = DBConsts::PolyDegree;
  std::stringstream query_stream;
  const size_t fst_dim_sz = pir_params.get_fst_dim_sz();
  const size_t useful_cnt = fst_dim_sz + pir_params.get_l() * (pir_params.get_num_dims() - 1);

  PirClient client(pir_params);
  PirServer server(pir_params);
  const size_t client_id = client.get_client_id();

  pir_params.print_params();

  // ============= setup the server ==============
  std::stringstream gsw_stream, data_stream;
  client.write_gsw_to_stream(client.generate_gsw_from_key(), gsw_stream);
  //--------------------------------------------------------------------------------
  server.set_client_bv_galois_key(client_id, client.create_bv_galois_keys());
  server.set_client_gsw_key(client_id, gsw_stream);

  // ============= Generate the query ==============
  const size_t query_idx = 253;
  seal::Ciphertext fast_seeded = client.fast_generate_query(query_idx);

  // ============= Serialize the query ==============
  seal::Ciphertext fast_query;
  fast_seeded.save(query_stream);
  fast_query.load(context_, query_stream);
  BENCH_PRINT("fast_query initial noise budget: " << client.noise_budget(fast_query) << " bits");
  auto fast_decrypted = client.decrypt_ct(fast_query);
  BENCH_PRINT("fast packed query: " << fast_decrypted.to_string());
  PRINT_BAR;

  // ============= Expand the query ==============
  auto fast_exp_q = server.fast_expand_qry(client_id, fast_query);
  BENCH_PRINT("fast_exp_q noise budget: " << client.noise_budget(fast_exp_q[query_idx % fst_dim_sz]) << " bits");

  std::vector<seal::Plaintext> fast_exp_pt;
  for (size_t i = 0; i < useful_cnt; i++) {
    fast_exp_pt.push_back(client.decrypt_ct(fast_exp_q[i]));
  }
  BENCH_PRINT("fast Expanded query: " << fast_exp_pt[query_idx % fst_dim_sz].to_string());
}
