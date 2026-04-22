#include "tests.h"
#include "rlwe.h"
#include <stdexcept>

// Pretty-print an RlwePt like seal::Plaintext::to_string (hex, high-deg first).
static std::string pt_to_string(const RlwePt &pt) {
  std::string s;
  bool first = true;
  for (size_t i = pt.data.size(); i > 0; i--) {
    uint64_t c = pt.data[i - 1];
    if (c == 0) continue;
    if (!first) s += " + ";
    first = false;
    char buf[64];
    if (i - 1 == 0)      std::snprintf(buf, sizeof(buf), "%lX", c);
    else if (i - 1 == 1) std::snprintf(buf, sizeof(buf), "%lXx", c);
    else                 std::snprintf(buf, sizeof(buf), "%lXx^%zu", c, i - 1);
    s += buf;
  }
  return first ? "0" : s;
}

// This is a BFV x GSW example
void PirTest::test_external_product() {
  print_func_name(__FUNCTION__);
  PirParams pir_params;
  const size_t coeff_count = DBConsts::PolyDegree;

  // ================== Create RGSW(1) ==================
  const size_t gsw_l = pir_params.get_l();
  const size_t base_log2 = pir_params.get_base_log2();
  GSWEval data_gsw(pir_params, gsw_l, base_log2);

  std::vector<uint64_t> one(coeff_count);
  std::vector<uint64_t> zero(coeff_count);
  one[0] = 1;

  const uint64_t q = pir_params.get_coeff_modulus()[0];
  const uint64_t t = pir_params.get_plain_mod();
  std::mt19937_64 rng(std::random_device{}());
  RlweSk rlwe_sk = gen_secret_key(coeff_count, q, rng);

  GSWCt one_gsw  = data_gsw.plain_to_gsw(one,  rlwe_sk, rng);
  GSWCt zero_gsw = data_gsw.plain_to_gsw(zero, rlwe_sk, rng);

  // ================== Create BFV(a) ==================
  std::vector<uint64_t> a(coeff_count);
  a[0] = t / 2 + 1; a[1] = t / 2 + 2; a[2] = t / 2 + 3;
  RlweCt a_encrypted;
  encrypt_bfv(a, rlwe_sk, coeff_count, q, t,
              pir_params.get_noise_std_dev(), rng, a_encrypted);

  // Expected plaintexts: BFV(a) * RGSW(1) = a, BFV(a) * RGSW(0) = 0.
  RlwePt expect_a;    expect_a.data = a;
  RlwePt expect_zero; expect_zero.data = zero;

  // ================== Test external product ==================
  RlweCt ext_prod_result;
  ext_prod_result.resize(coeff_count);
  RlwePt result;

  data_gsw.external_product(one_gsw, a_encrypted, ext_prod_result, LogContext::GENERIC);
  ext_prod_result.ntt_form = true;
  rlwe_ntt_inv_inplace(ext_prod_result, q, coeff_count);
  {
    int budget = decrypt_and_budget(ext_prod_result, rlwe_sk, coeff_count, q, t, result);
    BENCH_PRINT("BFV(a) * RGSW(1) = " << pt_to_string(result));
    BENCH_PRINT("Noise budget: " << budget);
    if (!utils::plaintext_is_equal(result, expect_a)) {
      throw std::runtime_error("BFV(a) * RGSW(1) != a");
    }
    if (budget <= 0) {
      throw std::runtime_error("BFV(a) * RGSW(1): non-positive noise budget");
    }
  }
  PRINT_BAR;

  data_gsw.external_product(zero_gsw, a_encrypted, ext_prod_result, LogContext::GENERIC);
  ext_prod_result.ntt_form = true;
  rlwe_ntt_inv_inplace(ext_prod_result, q, coeff_count);
  {
    int budget = decrypt_and_budget(ext_prod_result, rlwe_sk, coeff_count, q, t, result);
    BENCH_PRINT("BFV(a) * RGSW(0) = " << pt_to_string(result));
    BENCH_PRINT("Noise budget: " << budget);
    if (!utils::plaintext_is_equal(result, expect_zero)) {
      throw std::runtime_error("BFV(a) * RGSW(0) != 0");
    }
    if (budget <= 0) {
      throw std::runtime_error("BFV(a) * RGSW(0): non-positive noise budget");
    }
  }
  PRINT_BAR;

  // external product: BFV(a) * RGSW(1) for 100 times
  TIME_START("External product");
  for (size_t i = 0; i < 100; i++) {
    data_gsw.external_product(one_gsw, a_encrypted, ext_prod_result, LogContext::GENERIC);
  }
  TIME_END("External product");

  // ================== Approximate gadget decomposition ==================
  // Re-run external product with l' < l (so drop = q_bits - l'·base_log2 > 0)
  // using the approx decomposer + scaled gadget. Correctness: the external
  // product still lands at BFV(a) up to rounding error of magnitude
  // 2^(drop-1) per coefficient, which is absorbed by the noise budget.
  PRINT_BAR;
  BENCH_PRINT("=== Approximate decomposition ===");
  const size_t q_bits = pir_params.get_ct_mod_width();
  for (size_t l_approx = gsw_l; l_approx-- > 2;) {
    if (l_approx * base_log2 > q_bits) continue;
    const size_t drop = q_bits - l_approx * base_log2;
    GSWEval approx_gsw(pir_params, l_approx, base_log2);
    approx_gsw.set_approx_decomp(true);
    GSWCt one_gsw_approx  = approx_gsw.plain_to_gsw(one,  rlwe_sk, rng);
    GSWCt zero_gsw_approx = approx_gsw.plain_to_gsw(zero, rlwe_sk, rng);

    RlweCt r_one;  r_one.resize(coeff_count);
    approx_gsw.external_product(one_gsw_approx, a_encrypted, r_one, LogContext::GENERIC);
    r_one.ntt_form = true;
    rlwe_ntt_inv_inplace(r_one, q, coeff_count);
    RlwePt dec_one;
    int bud_one = decrypt_and_budget(r_one, rlwe_sk, coeff_count, q, t, dec_one);

    RlweCt r_zero; r_zero.resize(coeff_count);
    approx_gsw.external_product(zero_gsw_approx, a_encrypted, r_zero, LogContext::GENERIC);
    r_zero.ntt_form = true;
    rlwe_ntt_inv_inplace(r_zero, q, coeff_count);
    RlwePt dec_zero;
    int bud_zero = decrypt_and_budget(r_zero, rlwe_sk, coeff_count, q, t, dec_zero);

    BENCH_PRINT("l'=" << l_approx << " (drop=" << drop << " bits)");
    BENCH_PRINT("  BFV(a) * RGSW_approx(1) = " << pt_to_string(dec_one)
                << "  budget=" << bud_one);
    BENCH_PRINT("  BFV(a) * RGSW_approx(0) = " << pt_to_string(dec_zero)
                << "  budget=" << bud_zero);
    // Approximate decomposition introduces rounding error of magnitude
    // ~2^(drop-1) per coefficient before BFV scale-and-round. As long as the
    // noise budget stays positive the decrypted plaintext must still be exact.
    if (!utils::plaintext_is_equal(dec_one, expect_a)) {
      throw std::runtime_error("BFV(a) * RGSW_approx(1) != a at l'="
                               + std::to_string(l_approx));
    }
    if (!utils::plaintext_is_equal(dec_zero, expect_zero)) {
      throw std::runtime_error("BFV(a) * RGSW_approx(0) != 0 at l'="
                               + std::to_string(l_approx));
    }
    if (bud_one <= 0 || bud_zero <= 0) {
      throw std::runtime_error("Approximate decomp l'=" + std::to_string(l_approx)
                               + " exhausted noise budget");
    }
  }

  END_EXPERIMENT();
  PRINT_RESULTS();
}
