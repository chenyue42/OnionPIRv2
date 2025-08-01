#include "utils.h"
#include <fstream>
#include <stdexcept>


void utils::negacyclic_shift_poly_coeffmod(seal::util::ConstCoeffIter poly, size_t coeff_count,
                                           size_t shift, const seal::Modulus &modulus,
                                           seal::util::CoeffIter result) {
  if (shift == 0) {
    set_uint(poly, coeff_count, result);
    return;
  }

  uint64_t index_raw = shift;
  const uint64_t coeff_count_mod_mask = static_cast<uint64_t>(coeff_count) - 1;
  for (size_t i = 0; i < coeff_count; i++, poly++, index_raw++) {
    uint64_t index = index_raw & coeff_count_mod_mask;  // shifted index, possibly wrapping around
    if (!(index_raw & static_cast<uint64_t>(coeff_count)) || !*poly) {
      // for those entries that are not wrapped around
      result[index] = *poly;
    } else {
      // For wrapped around entries, we fill in additive inverse.
      result[index] = modulus.value() - *poly; 
    }
  }
}

void utils::shift_polynomial(seal::EncryptionParameters &params, seal::Ciphertext &encrypted,
                             seal::Ciphertext &destination, size_t index) {
  const auto coeff_count = DatabaseConstants::PolyDegree;
  const auto rns_mod_cnt = params.coeff_modulus().size() - 1;
  destination = encrypted;
  for (size_t i = 0; i < 2; i++) {  // two polynomials in ciphertext
    for (size_t j = 0; j < rns_mod_cnt; j++) {
      negacyclic_shift_poly_coeffmod(encrypted.data(i) + (j * coeff_count), coeff_count, index,
                                     params.coeff_modulus()[j],
                                     destination.data(i) + (j * coeff_count));
    }
  }
}


std::string utils::uint128_to_string(uint128_t value) {
    // Split the 128-bit value into two 64-bit parts
    uint64_t high = value >> 64;
    uint64_t low = static_cast<uint64_t>(value);

    std::ostringstream oss;

    // Print the high part, if it's non-zero, to avoid leading zeros
    if (high != 0) {
        oss << high << " * 2^64 + " << low;
    } else {
        oss << low;
    }
    return oss.str();
}



std::vector<std::vector<uint64_t>> utils::gsw_gadget(size_t l, uint64_t base_log2, size_t rns_mod_cnt,
                const std::vector<seal::Modulus> &coeff_modulus) {
  // Create RGSW gadget.
  std::vector<std::vector<uint64_t>> gadget(rns_mod_cnt, std::vector<uint64_t>(l));
  for (size_t i = 0; i < rns_mod_cnt; i++) {
    const uint128_t mod = coeff_modulus[i].value();
    uint128_t pow = 1;
    for (int j = l - 1; j >= 0; j--) {
      gadget[i][j] = pow;
      pow = (pow << base_log2) % mod;
    }
  }
  return gadget;
}


/**
 * @brief Generate the smallest prime that is at least bit_width bits long.
 * @param bit_width >= 2 and <= 64
 * @return std::uint64_t  
 */
std::uint64_t utils::generate_prime(size_t bit_width) {
  if (bit_width < 2) throw std::invalid_argument("Bit width must be at least 2.");

  // Otherwise, generate a new prime
  std::uint64_t candidate = 1ULL << (bit_width - 1);
  do {
      candidate++;
      // Ensure candidate is odd, as even numbers greater than 2 cannot be prime
      candidate |= 1;
  } while (!seal::util::is_prime(seal::Modulus(candidate)));

  BENCH_PRINT("Plaintext prime: " << candidate);
  return candidate;
}

// converting a uint64_t to a std::vector<uint8_t> of size 8. Assyming the input vector has at least 8 elements.
void utils::writeIdxToEntry(const uint64_t idx, Entry &entry) {
  // Convert id to bytes and write them to the start of the entry.
  for (size_t i = 0; i < 8; ++i) {
    // Extract the i-th byte from the least significant to the most significant
    entry[7 - i] = static_cast<uint8_t>((idx >> (i * 8)) & 0xFF);
  }
}

uint64_t utils::get_entry_idx(const Entry &entry) {
  uint64_t idx = 0;
  for (size_t i = 0; i < 8; ++i) {
    idx |= static_cast<uint64_t>(entry[7 - i]) << (i * 8);
  }
  return idx;
}


void utils::print_entry(const Entry &entry, const size_t count) {
  size_t cnt = 0;
  for (auto &val : entry) {
    if (cnt < count) { 
      std::cout << (size_t)val << ", ";
    }
    cnt += 1;
  }
  std::cout << std::endl;
}


bool utils::entry_is_equal(const Entry &entry1, const Entry &entry2) {
  for (size_t i = 0; i < entry1.size(); i++) {
    if (entry1[i] != entry2[i]) {
      std::cerr << "Entries are not equal" << std::endl;
      return false;
    }
  }
  std::cout << "Entries are equal" << std::endl;
  return true;
}


void utils::print_progress(size_t current, size_t total) {
    float progress = static_cast<float>(current) / total;
    size_t bar_width = 70;

    // Move the cursor to the beginning and clear the line.
    std::cout << "\r\033[K[";

    size_t pos = static_cast<size_t>(bar_width * progress);
    for (size_t i = 0; i < bar_width; ++i) {
        if (i < pos)
            std::cout << "=";
        else if (i == pos)
            std::cout << ">";
        else
            std::cout << " ";
    }
    std::cout << "] " << size_t(progress * 100.0) << " %";
    std::cout.flush();
}


Entry utils::generate_entry(const uint64_t entry_id, const size_t entry_size, std::ifstream &random_file) {
  Entry entry(entry_size);

  // write the entry_id to the first 8 bytes of the entry
  utils::writeIdxToEntry(entry_id, entry);

  // fill the rest of the entry with random bytes
  // random_file.read(reinterpret_cast<char *>(entry.data() + 8), entry_size - 8);
  for (size_t i = 8; i < entry_size; ++i) {
    entry[i] = static_cast<uint8_t>(128);
  }
  return entry;
}


size_t utils::next_pow_of_2(const size_t n) {
  size_t p = 1;
  while (p < n) {
    p <<= 1;
  }
  return p;
}

size_t utils::roundup_div(const size_t numerator, const size_t denominator) {
  if (denominator == 0) {
    throw std::invalid_argument("roundup_div division by zero");
  }
  return (numerator + denominator - 1) / denominator;
}

void utils::fill_rand_arr(uint64_t *arr, size_t size) {
  std::ifstream rand_file("/dev/urandom", std::ios::binary);
  rand_file.read(reinterpret_cast<char *>(arr), size * sizeof(uint64_t));
  rand_file.close();
}
