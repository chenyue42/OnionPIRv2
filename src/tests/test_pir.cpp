#include "tests.h"
#include "bv_keyswitch.h"

void PirTest::test_pir() {
  print_func_name(__FUNCTION__);
  auto success_count = 0;

  // ============== setting parameters for PIR scheme ==============
  PirParams pir_params;
  pir_params.print_params();
  PirServer server(pir_params); // Initialize the server with the parameters

  // Pre-generate all query indices so gen_data() only records what we need
  srand(time(0));
  const size_t num_pt = pir_params.get_num_pt();
  std::vector<size_t> query_indices(num_experiments);
  for (size_t i = 0; i < num_experiments; i++) {
    query_indices[i] = rand() % num_pt;
  }

  BENCH_PRINT("Initializing server...");
  server.gen_data(query_indices);
  BENCH_PRINT("Server initialized");

  // some global results
  size_t galois_key_size = 0;
  size_t query_size = 0;
  size_t resp_size = 0;

  if constexpr (DBConsts::Mode == DBConsts::QueryMode::DoubleStateless) {
    BENCH_PRINT("Query mode: DoubleStateless (DMux expansion, no stored keys)");
  } else {
    BENCH_PRINT("Query mode: Stateful (Galois expansion, server-resident keys)");
  }

  // Run the query process many times.
  for (size_t i = 0; i < num_experiments; i++) {
    BENCH_PRINT("======================== Experiment " << i + 1 << " ========================");

    // Initialize the client
    PirClient client(pir_params);
    const size_t client_id = client.get_client_id();
    std::stringstream resp_stream;
    size_t query_pt_idx = query_indices[i];
    RlweCt response;

    if constexpr (DBConsts::Mode == DBConsts::QueryMode::Stateful) {
      // ============= OFFLINE PHASE: server-resident key materials ==============
      auto bv_galois_keys = client.create_bv_galois_keys();
      galois_key_size = pir_params.get_bv_galois_key_size();
      server.set_client_bv_galois_key(client_id, std::move(bv_galois_keys));
      server.set_client_gsw_key(client_id, client.generate_gsw_from_key());

      // ===================== ONLINE PHASE =====================
      TIME_START(CLIENT_TOT_TIME);
      RlweCt query = client.fast_generate_query(query_pt_idx);
      TIME_END(CLIENT_TOT_TIME);
      query_size = pir_params.get_BFV_size();

      TIME_START(SERVER_TOT_TIME);
      response = server.make_query(client_id, query);
      TIME_END(SERVER_TOT_TIME);
    } else {
      // ============= DOUBLE STATELESS: fresh selectors, no stored keys ==========
      galois_key_size = 0;
      TIME_START(CLIENT_TOT_TIME);
      // The client ships a real BFV(1) root for the DMux tree plus the fresh
      // RGSW selectors; the server fabricates no part of the query.
      std::vector<RlweCt> first_query;
      first_query.push_back(client.fresh_bfv_ct(1));
      auto first_sel = client.generate_dmux_selectors(query_pt_idx, pir_params.get_l());
      auto other_sel = client.generate_other_dim_selectors(query_pt_idx);
      TIME_END(CLIENT_TOT_TIME);
      // Each RGSW selector is 2*l_ep seed-compressed BFV ciphertexts; the root is
      // one full (non-seeded) BFV ciphertext.
      const size_t num_gsw = first_sel.size() + other_sel.size();
      query_size = first_query.size() * pir_params.get_BFV_size(/*use_seed=*/false)
                 + num_gsw * 2 * pir_params.get_l() * pir_params.get_BFV_size();

      TIME_START(SERVER_TOT_TIME);
      response = server.make_query_dmux(std::move(first_query), first_sel, other_sel);
      TIME_END(SERVER_TOT_TIME);
    }

    // ---------- server send the response to the client -----------
    resp_size = server.save_resp_to_stream(response, resp_stream);

    // ============= CLIENT ===============
    // client gets result from the server and decrypts it
    RlweCt reconstructed_result = client.load_resp_from_stream(resp_stream);
    TIME_START(CLIENT_TOT_TIME);
    RlwePt decrypted_result = client.decrypt_mod_q(reconstructed_result);
    TIME_END(CLIENT_TOT_TIME);

    // ============= Directly get the plaintext from server. Not part of PIR.
    RlwePt actual_plaintext = server.direct_get_original_plaintext(query_pt_idx);

    END_EXPERIMENT();
    // ============= PRINTING RESULTS ===============
    // DEBUG_PRINT("\t\tquery / resp / actual idx:\t" << query_pt_idx << " / " << resp_plaintext_idx << " / " << actual_plaintext_idx);

    if (utils::plaintext_is_equal(decrypted_result, actual_plaintext)) {
      // print a green success message
      std::cout << color_green() << "Success!" << color_reset() << std::endl;
      success_count++;
    } else {
      // print a red failure message
      std::cout << color_red() << "Failure!" << color_reset() << std::endl;
      std::cout << "Query index:\t" << query_pt_idx << std::endl;
      std::cout << "PIR Result:\t";
      utils::print_plaintext(decrypted_result, 20);
      std::cout << "Actual Plaintext:\t";
      utils::print_plaintext(actual_plaintext, 20);
    }
  }

  double avg_server_time = GET_AVG_TIME(SERVER_TOT_TIME);
  double throughput = pir_params.get_DBSize_MB() / (avg_server_time / 1000);

  // ============= PRINTING FINAL RESULTS ===============]
  PRINT_BAR;
  BENCH_PRINT("                                FINAL RESULTS")
  PRINT_BAR;
  BENCH_PRINT("Success rate: " << success_count << "/" << num_experiments);
  BENCH_PRINT("BV galois key size: " << static_cast<double>(galois_key_size) / 1024 << " KB");
  // DoubleStateless ships nothing server-side: no galois keys, no RGSW(sk).
  const size_t gsw_key_size_bytes =
      (DBConsts::Mode == DBConsts::QueryMode::Stateful)
          ? pir_params.get_gsw_key_size()
          : 0;
  BENCH_PRINT("gsw key size: " << gsw_key_size_bytes << " bytes = " << static_cast<double>(gsw_key_size_bytes) / 1024 << " KB");
  BENCH_PRINT("total key size: " << static_cast<double>(galois_key_size + gsw_key_size_bytes) / 1024 << "KB");
  BENCH_PRINT("query size: " << query_size << " bytes = " << static_cast<double>(query_size) / 1024 << " KB");
  BENCH_PRINT("response size: " << resp_size << " bytes = " << static_cast<double>(resp_size) / 1024 << " KB");

  PRETTY_PRINT();
  BENCH_PRINT("Server throughput: " << throughput << " MB/s");
}
