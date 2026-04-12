# Seeded GSW Key Generation (Removed) — Reference

This file captures the old, seed-based RGSW(sk) key generation and seeded
symmetric query encryption that were removed when we stopped serializing the
GSW key and query through SEAL streams.

## Why it was removed

The SEAL "seeded" encryption path stores `c1` as a PRNG seed marker + seed bytes
instead of the actual uniform polynomial `a`. `c1` is only regenerated from the
seed when the ciphertext is deserialized via `seal::Ciphertext::load()`.

When we decided to skip the serialize/deserialize round-trip for the GSW key
and the query (because BV key-switching no longer needs the special prime),
the seeded ciphertexts became unusable: `c1` was never regenerated, so every
row was effectively garbage and decryption failed (noise budget 0).

The fix is to use the already-existing, fully-materialized path:
`GSWEval::plain_to_gsw_one_row` (which uses `encryptor.encrypt_zero_symmetric`
non-seeded) and `Encryptor::encrypt_symmetric` for the query.

---

## Removed functions (`src/gsw_eval.cpp`)

### `plain_to_half_gsw`

```cpp
void GSWEval::plain_to_half_gsw(std::vector<uint64_t> const &plaintext,
                                   seal::Encryptor const &encryptor,
                                   seal::SecretKey const &sk,
                                   std::vector<seal::Ciphertext> &output) {
  output.clear();
  // when poly_id = 0, we are working on the first half of the GSWCiphertext
  for (size_t poly_id = 0; poly_id < 2; poly_id++) {
    for (size_t k = 0; k < l_; k++) {
      seal::Ciphertext cipher;
      plain_to_half_gsw_one_row(plaintext, encryptor, sk, poly_id, k, cipher);
      output.push_back(cipher);
    }
  }
}
```

### `plain_to_half_gsw_one_row`

```cpp
void GSWEval::plain_to_half_gsw_one_row(std::vector<uint64_t> const &plaintext,
                                  seal::Encryptor const &encryptor,
                                  seal::SecretKey const &sk, const size_t half,
                                  const size_t level, seal::Ciphertext &output) {

  // Accessing context data within this function instead of passing these parameters
  const auto &context = pir_params_.get_context();
  const auto &params = context.first_context_data()->parms();
  constexpr size_t coeff_count = DBConsts::PolyDegree;
  const auto &coeff_modulus = pir_params_.get_coeff_modulus();
  const size_t rns_mod_cnt = coeff_modulus.size();
  assert(plaintext.size() == coeff_count * rns_mod_cnt || plaintext.size() == coeff_count);

  // Create RGSW gadget.
  std::vector<std::vector<uint64_t>> gadget = utils::gsw_gadget(l_, base_log2_, rns_mod_cnt, coeff_modulus);

  // ================== Second half of the seeded GSW ==================
  if (half == 1) {
    // extract the level column of gadget
    std::vector<uint64_t> col;
    for (size_t i = 0; i < rns_mod_cnt; i++) {
      col.push_back(gadget[i][level]);
    }
    seal::util::prepare_seeded_gsw_key(sk, col, context,
                                       params.parms_id(), false, output);
    return;
  }

  // ================== Other cases ==================
  assert(half == 0);
  // If we are at the first half of the GSW, we are adding new things to the
  // first polynomial (c0) of the given BFV ciphertext. c1 is not touched.
  encryptor.encrypt_zero_symmetric_seeded(output);
  auto ct = output.data(0);
  // Many(2) moduli are used
  for (size_t mod_id = 0; mod_id < rns_mod_cnt; mod_id++) {
    size_t pad = (mod_id * coeff_count);
    inter_coeff_t mod = coeff_modulus[mod_id].value();
    uint64_t gadget_coef = gadget[mod_id][level];
    auto pt = plaintext.data();
    if (plaintext.size() == coeff_count * rns_mod_cnt) {
      pt = plaintext.data() + pad;
    }
    // Loop through plaintext coefficients
    for (size_t j = 0; j < coeff_count; j++) {
      uint64_t val = (inter_coeff_t)pt[j] * gadget_coef % mod;
      ct[j + pad] =
          static_cast<uint64_t>((ct[j + pad] + val) % mod);
    }
  }
}
```

---

## Removed callers (`src/client.cpp`)

### Old `generate_gsw_from_key`

```cpp
std::vector<Ciphertext> PirClient::generate_gsw_from_key() {
  std::vector<seal::Ciphertext> gsw_enc; // temporary GSW ciphertext using seal::Ciphertext
  const auto sk_ = secret_key_.data();
  const auto ntt_tables = context_.first_context_data()->small_ntt_tables();
  const size_t rns_mod_cnt = pir_params_.get_rns_mod_cnt();
  const size_t coeff_count = DBConsts::PolyDegree;
  std::vector<uint64_t> sk_ntt(sk_.data(), sk_.data() + coeff_count * rns_mod_cnt);

  RNSIter secret_key_iter(sk_ntt.data(), coeff_count);
  inverse_ntt_negacyclic_harvey(secret_key_iter, rns_mod_cnt, ntt_tables);

  GSWEval key_gsw(pir_params_, pir_params_.get_l_key(), pir_params_.get_base_log2_key());
  key_gsw.plain_to_half_gsw(sk_ntt, encryptor_, secret_key_, gsw_enc);
  return gsw_enc;
}
```

### Old `fast_generate_query` query encryption line

```cpp
// Encrypt plain_query first. Later we will insert the rest. $\tilde c$ in paper
seal::Ciphertext query;
encryptor_.encrypt_symmetric_seeded(plain_query, query);
```

---

## Custom SEAL function (still present in SEAL-For-OnionPIR)

The `seal::util::prepare_seeded_gsw_key` function lives at
`/u/yuec12/SEAL-For-OnionPIR/native/src/seal/util/rlwe.cpp` and is no longer
referenced from OnionPIRv2. It can remain in the SEAL fork for reference, but
the bug to be aware of is at lines ~499-500:

```cpp
// c1 contains the actual uniform `a` polynomial up to this point.
// Then it gets clobbered with the seed marker + seed bytes for serialization:
c1[0] = static_cast<uint64_t>(0xFFFFFFFFFFFFFFFFULL);
prng_info.save(reinterpret_cast<seal_byte *>(c1 + 1), prng_info_byte_count, compr_mode_type::none);
```

Any caller that bypasses stream serialization will see a garbage `c1`.

---

## Replacement (current code)

The new `generate_gsw_from_key` directly loops over the `plain_to_gsw_one_row`
non-seeded path (which was already used by `test_ext_prod` / `test_ext_prod_mux`).
It leverages the fact that writing `plaintext * B^i` into `c1` for the second
half (rather than into `c0`) still yields a row that behaves correctly under the
external-product sum, because decryption of the row gives
`s * plaintext * B^i + e = sk^2 * B^i + e` when `plaintext = sk`.

The new query path uses `encryptor_.encrypt_symmetric(plain_query, query)` —
fully materialized, no seed trick.
