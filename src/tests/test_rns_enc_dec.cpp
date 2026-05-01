#include "tests.h"
#include "pir.h"
#include "rlwe.h"

#include <random>
#include <sstream>
#include <stdexcept>

// Round-trip test for the K-limb (RNS) RLWE primitives:
//   gen_secret_key_rns / encrypt_zero_rns / encrypt_bfv_rns / decrypt_rns.
// Uses the active PirParams config — runs at whatever K = rns_mods.size() the
// build was configured for. At K=1 the K-aware path is also exercised; the
// existing single-mod helpers are independent and unaffected.

void PirTest::test_rns_enc_dec() {
  print_func_name(__FUNCTION__);

  PirParams pir_params;
  const size_t N = DBConsts::PolyDegree;
  const std::vector<uint64_t> qs(pir_params.get_rns_mods().begin(),
                                 pir_params.get_rns_mods().end());
  const uint64_t t = pir_params.get_plain_mod();
  const double sigma = pir_params.get_noise_std_dev();
  const RnsTables &tables = pir_params.get_rns_tables();

  BENCH_PRINT("K=" << qs.size() << " N=" << N << " t=" << t);

  std::mt19937_64 rng(0xDEADBEEFULL);
  RlweSk sk = gen_secret_key_rns(N, qs, rng);

  // --- Encrypt(0) → Decrypt = 0 ---
  {
    RlweCt ct;
    encrypt_zero_rns(sk, N, qs, sigma, rng, ct);
    RlwePt pt;
    decrypt_rns(ct, sk, N, qs, t, tables, pt);
    for (size_t i = 0; i < N; i++) {
      if (pt.data[i] != 0) {
        std::ostringstream os;
        os << "Encrypt(0) → Decrypt nonzero at coef " << i << ": got " << pt.data[i];
        throw std::runtime_error(os.str());
      }
    }
    BENCH_PRINT("Encrypt(0) → Decrypt = 0 verified");
  }

  // --- Encrypt(m) → Decrypt = m for random m ---
  {
    std::vector<uint64_t> m(N);
    for (size_t i = 0; i < N; i++) m[i] = rng() % t;

    RlweCt ct;
    encrypt_bfv_rns(m, sk, N, qs, t, sigma, rng, ct);
    RlwePt pt;
    decrypt_rns(ct, sk, N, qs, t, tables, pt);
    for (size_t i = 0; i < N; i++) {
      if (pt.data[i] != m[i]) {
        std::ostringstream os;
        os << "Encrypt(m) → Decrypt mismatch at coef " << i
           << ": got " << pt.data[i] << " want " << m[i];
        throw std::runtime_error(os.str());
      }
    }
    BENCH_PRINT("Encrypt(m) → Decrypt = m verified for random m");
  }

  // --- multiply Enc(m) by 2 and check decryption ---
  {
    std::vector<uint64_t> m(N);
    for (size_t i = 0; i < N; i++) m[i] = rng() % t;

    RlweCt ct;
    encrypt_bfv_rns(m, sk, N, qs, t, sigma, rng, ct);
    // multiply the ciphertext by 2 (in-place) to check that decryption reflects the change.
    for (size_t k = 0; k < qs.size(); k++) {
      const uint64_t qk = qs[k];
      for (size_t i = 0; i < N; i++) {
        const size_t idx = k * N + i;
        ct.c0[idx] = static_cast<uint64_t>((static_cast<uint128_t>(ct.c0[idx]) * 2) % qk);
        ct.c1[idx] = static_cast<uint64_t>((static_cast<uint128_t>(ct.c1[idx]) * 2) % qk);
      }
    }

    RlwePt pt;
    decrypt_rns(ct, sk, N, qs, t, tables, pt);
    for (size_t i = 0; i < N; i++) {
      uint64_t expected = (m[i] * 2) % t;
      if (pt.data[i] != expected) {
        std::ostringstream os;
        os << "Encrypt(m)*2 → Decrypt mismatch at coef " << i
           << ": got " << pt.data[i] << " want " << expected;
        throw std::runtime_error(os.str());
      }
    }
    BENCH_PRINT("Encrypt(m)*2 → Decrypt verified for random m");
  }

  BENCH_PRINT("All checks passed.");
}
