#include <cstdio>
#include <cstdint>
#include <random>
#include <iostream>
#include <cassert>
#include "DES.h"

#include <pybind11/pybind11.h>
#include <torch/extension.h>

struct round_constant_t {
  std::vector<int> plidx;
  std::vector<int> phidx;
  std::vector<int> clidx;
  std::vector<int> chidx;
  std::vector<int> fidx;
  std::vector<std::pair<int, int>> round_idx_pair;
};

// Guide
// for R-round attack, lookup the (R-1) round formula
// then pass extract_lhs_bits in this order:
// 1. PH index
// 2. PL index
// 3. CL index
// 4. CH index
// 5. PL index
// 6. round = 1
// for extract_rhs_bits:
// for each K, {round + 1, index}

round_constant_t ROUNDS[17] = {
  {}, {}, {}, {},
  // ROUND 4
  {
    {7, 18, 24, 29}, {15}, {15}, {7, 18, 24, 29}, {15},
    {{2, 22}, {4, 22}}
  },
  // ROUND 5
  {
    {7, 18, 24, 29}, {15}, {7, 18, 24, 29, 27, 28, 30, 31}, {15}, {15},
    {{2, 22}, {4, 22}, {5, 42}, {5, 43}, {5, 45}, {5, 46}}
  }, 
  {}, {},
  // ROUND 8
  {
    {7, 18, 24}, {12, 16}, {15}, {7, 18, 24, 29}, {12, 16},
    {{2, 19}, {2, 23}, {4, 22}, {5, 44}, {6, 22}, {8, 22}}
  }
};

// hex : 01 23 45 67 89 AB CD EF
// bin : 00000001 00100011 01000101 01100111 10001001 10101011 11001101 11101111
// paper style index (right-to-left)
// 63 62 61 60 59 58 57 56  | 55 54 53 52 51 50 49 48  | ...
// DES-Python style index (left-to-right) (little-endian)
// 0  1  2  3  4  5  6  7   | 8  9  10 11 12 13 14 15  | ...
// DES-C style index (left-to-right but right-to-left inside a byte) (big-endian)
// 7  6  5  4  3  2  1  0   | 15 14 13 12 11 10 9  8   | ...
// S1        | S2           | S3 ...

// index conversion
int paper2big(int i, int n) {
  return n - 1 - (i / 8) * 8 - (7 - (i % 8));
}

int big2paper(int i, int n) {
  return n - 1 - (i / 8) * 8 - (7 - (i % 8));
}

int big2little(int i) {
  return (i / 8) * 8 + (7 - (i % 8));
}

int little2big(int i) {
  return (i / 8) * 8 + (7 - (i % 8));
}

std::vector<int> find_effective_k_bits(int output_index, int round) {
  int x = paper2big(output_index, 32);
  // keep c-style index after this
  auto y = DES_P_BOX[big2little(x)];
  x = y.byte * 8 + __builtin_ctz(y.mask); // index before P permutation
  x = big2little(x) / 4; // S-box index (0~7)
  // Sbox 7 -> key msb 6bits, ..., Sbox 0 ->  key lsb 6bits
  // -> cand = x * 6 ~ x * 6 + 5
  std::vector<int> ret;
  for (int cand = x * 6; cand < x * 6 + 6; ++cand) {
    auto y = DES_PC2_BOX[cand]; // PC2 is be indexed
    int x = y.byte * 8 + __builtin_ctz(y.mask); // index before PC2 permutation
    x = big2little(x); // le is easier to calculate here
    int offset = x >= 28 ? 28 : 0;
    x -= offset;
    for (int i = 0; i < round; ++i) {
      x = (x + DES_SHIFT_BOX[i]) % 28;
    }
    x += offset;
    y = DES_PC1_BOX[x]; // 0 ~ 56
    x = y.byte * 8 + __builtin_ctz(y.mask); // index before PC1 permutation
    ret.push_back(x);
  }
  return ret;
}

uint64_t test(uint64_t a, uint64_t b) {
  return a + b;
}

void printhex(uint64_t x) {
  for (int i = 0; i < 64; i += 8) {
    printf("%02lX", (x >> i) & 0xff);
  }
  printf("\n");
}

void printbin(uint64_t x) {
  for (int i = 0; i < 64; ++i) {
    printf("%lu", (x >> little2big(i)) & 1);
  }
  printf("\n");
}

std::vector<int> extract_lhs_bits(uint64_t pt, uint64_t ct, uint64_t *rk,
    std::vector<int> plidx, std::vector<int> phidx, std::vector<int> clidx, std::vector<int> chidx,
    std::vector<int> fidx, int round) {
  uint64_t pt_permd = 0, ct_permd = 0;
	permutation((uint8_t*)&pt, DES_IP_BOX, 8, (uint8_t*)&pt_permd);
	permutation((uint8_t*)&ct, DES_IP_BOX, 8, (uint8_t*)&ct_permd);
  std::vector<int> ret;
  for (int i : plidx) {
    ret.push_back((pt_permd >> paper2big(i, 64)) & 1);
  }
  for (int i : phidx) {
    ret.push_back((pt_permd >> paper2big(i, 32)) & 1);
  }
  for (int i : clidx) {
    ret.push_back((ct_permd >> paper2big(i, 64)) & 1);
  }
  for (int i : chidx) {
    ret.push_back((ct_permd >> paper2big(i, 32)) & 1);
  }
  uint32_t f = 0;
  if (round == 1) {
    feistel(((uint8_t*)&pt_permd) + 4, (uint8_t*)&rk[round - 1], (uint8_t*)&f);
  } else {
    feistel(((uint8_t*)&ct_permd) + 4, (uint8_t*)&rk[round - 1], (uint8_t*)&f);
  }
  for (int i : fidx) {
    ret.push_back((f >> paper2big(i, 32)) & 1);
  }
  return ret;
}

std::vector<int> extract_rhs_bits(uint64_t *rk, std::vector<std::pair<int, int>> round_idx_pair) {
  std::vector<int> ret;
  for (auto p : round_idx_pair) {
    int round = p.first;
    int i = p.second;
    ret.push_back((rk[round - 1] >> paper2big(i, 48)) & 1);
  }
  return ret;
}

//void test_k_iteration() {
//  std::default_random_engine gen(42);
//  std::uniform_int_distribution<uint64_t> dist;
//  uint64_t K = dist(gen);
//  uint64_t roundKeys[16];
//  DES_CreateKeys((uint8_t*)&K, (uint8_t(*)[8])roundKeys);
//  std::vector<uint64_t> PTs, CTs;
//  int n = 10000;
//  for (int i = 0; i < n; i++) {
//    uint64_t PT = dist(gen);
//    uint64_t CT = 0;
//    DES_Encrypt((uint8_t*)&PT, (uint8_t(*)[8])roundKeys, (uint8_t*)&CT, 4);
//    PTs.push_back(PT);
//    CTs.push_back(CT);
//  }
//  auto effkidx = find_effective_k_bits(15, 1);
//  printf("effkidx: ");
//  for (int i : effkidx) {
//    printf("%d ", i);
//  }
//  printf("\n");
//  size_t effkidx_sz = effkidx.size();
//  for (int mask = 0; mask < (1 << effkidx_sz); ++mask) {
//  //for (int i = 0; i < 64; ++i) {
//    uint64_t newK = 0;
//    for (int i = 0; i < effkidx_sz; ++i) {
//      if (mask & (1 << i)) {
//        newK |= 1UL << effkidx[i];
//      }
//    }
//    //newK |= 1UL << i;
//    uint64_t newRK[16];
//    DES_CreateKeys((uint8_t*)&newK, (uint8_t(*)[8])newRK);
//    int cnt = 0;
//    for (int i = 0; i < n; ++i) {
//      auto lhs_bits = extract_lhs_bits(PTs[i], CTs[i], newRK, {7, 18, 24, 29}, {15}, {15}, {7, 18, 24, 29}, {15}, 1);
//    //printf("lhs_bits:");
//    //for (int b : lhs_bits) {
//    //  printf(" %d", b);
//    //}
//    //printf("\n");
//      int lhs_xor = 0;
//      for (int b : lhs_bits) {
//        lhs_xor ^= b;
//      }
//      if (lhs_xor == 0) {
//        cnt++;
//      }
//    }
//    printf("cnt: %d newK: ", cnt); printbin(newK);
//  }
//  printf("original K: "); printbin(K);
//}

std::default_random_engine global_gen;

void set_seed(uint64_t seed) {
  global_gen.seed(seed);
}

int get_model_input_size(int round) {
  return ROUNDS[round].plidx.size() + ROUNDS[round].phidx.size() + ROUNDS[round].clidx.size() + ROUNDS[round].chidx.size() + ROUNDS[round].fidx.size();
}

void gen_dataset(size_t dataset_sz, torch::Tensor& x, torch::Tensor& y, int round, bool hou_style) {
  std::uniform_int_distribution<uint64_t> pt_dist;
  std::uniform_int_distribution<uint64_t> k_dist;
  std::uniform_int_distribution<uint64_t> y_dist(0, 1);

  int ref_count = 0;
  for (int i = 0; i < dataset_sz; i++) {
    uint64_t PT = pt_dist(global_gen);
    uint64_t Y;
    uint64_t K;
    uint64_t roundKeys[round];
    int rhs_xor;

    if (hou_style) {
      while (true) {
        K = k_dist(global_gen);
        DES_CreateKeys((uint8_t*)&K, (uint8_t(*)[8])roundKeys, round);
        auto rhs_bits = extract_rhs_bits(roundKeys, ROUNDS[round].round_idx_pair);
        rhs_xor = 0;
        for (int b : rhs_bits) rhs_xor ^= b;
        if (rhs_xor == 0) break;
      }
    } else {
      K = k_dist(global_gen);
      DES_CreateKeys((uint8_t*)&K, (uint8_t(*)[8])roundKeys, round);
      auto rhs_bits = extract_rhs_bits(roundKeys, ROUNDS[round].round_idx_pair);
      rhs_xor = 0;
      for (int b : rhs_bits) rhs_xor ^= b;
    }

    uint64_t CT = 0;
    DES_Encrypt((uint8_t*)&PT, (uint8_t(*)[8])roundKeys, (uint8_t*)&CT, round);
    auto lhs_bits = extract_lhs_bits(PT, CT, roundKeys, ROUNDS[round].plidx, ROUNDS[round].phidx, ROUNDS[round].clidx, ROUNDS[round].chidx, ROUNDS[round].fidx, 1);

    int lhs_xor = 0;
    for (int b : lhs_bits) lhs_xor ^= b;

    if (lhs_xor == rhs_xor) ref_count++;

    // Create label
    if (hou_style) {
      Y = y_dist(global_gen);
      if (Y == 0) { // fill random for negative sample
        for (int j = 0; j < ROUNDS[round].fidx.size(); ++j) {
          lhs_bits[lhs_bits.size() - 1 - j] = y_dist(global_gen);
        }
      }
    } else {
      Y = rhs_xor;
    }

    for (int j = 0; j < lhs_bits.size(); ++j) {
      x[i][j] = (float)lhs_bits[j];
    }
    y[i] = (long)Y;
  }
  printf("reference accuracy: %f (%d / %ld)\n", (double)ref_count / dataset_sz, ref_count, dataset_sz);
}

void gen_pair_with_key(size_t dataset_sz, py::list& pt_list, py::list& ct_list, uint64_t key, int round) {
  std::uniform_int_distribution<uint64_t> pt_dist;
  for (int i = 0; i < dataset_sz; i++) {
    uint64_t PT = pt_dist(global_gen);
    uint64_t roundKeys[round];
    DES_CreateKeys((uint8_t*)&key, (uint8_t(*)[8])roundKeys, round);
    uint64_t CT = 0;

    // 4-round attack
    DES_Encrypt((uint8_t*)&PT, (uint8_t(*)[8])roundKeys, (uint8_t*)&CT, round);

    pt_list.append(PT);
    ct_list.append(CT);
  }
}

void gen_key_cand_as_intdiff(py::list key_cand, int round) {
  assert(ROUNDS[round].fidx.size() == 1);
  auto effkidx = find_effective_k_bits(ROUNDS[round].fidx.back(), 1);
  printf("effective k bits: ");
  for (int i : effkidx) {
    printf(" %d", big2paper(i, 64));
  }
  printf("\n");
  size_t effkidx_sz = effkidx.size();
  for (int mask = 0; mask < (1 << effkidx_sz); ++mask) {
    uint64_t newK = 0;
    for (int i = 0; i < effkidx_sz; ++i) {
      if (mask & (1 << i)) {
        newK |= 1UL << effkidx[i];
      }
    }
    key_cand.append(newK);
  }
}

void extract_lhs(size_t npair, py::list pts, py::list cts, py::list key_cand, torch::Tensor& lhs, int round) {
  int ncand = key_cand.size();
  for (int j = 0; j < ncand; ++j) {
    uint64_t K = key_cand[j].cast<uint64_t>();
    uint64_t roundKeys[round];
    DES_CreateKeys((uint8_t*)&K, (uint8_t(*)[8])roundKeys, round);
    for (int i = 0; i < npair; i++) {
      uint64_t PT = pts[i].cast<uint64_t>();
      uint64_t CT = cts[i].cast<uint64_t>();
      auto lhs_bits = extract_lhs_bits(PT, CT, roundKeys, ROUNDS[round].plidx, ROUNDS[round].phidx, ROUNDS[round].clidx, ROUNDS[round].chidx, ROUNDS[round].fidx, 1);
      for (int k = 0; k < lhs_bits.size(); ++k) {
        lhs[i][j][k] = (float)lhs_bits[k];
      }
    }
  }
}

int check_rhs(uint64_t key, int round) {
  uint64_t roundKeys[round];
  DES_CreateKeys((uint8_t*)&key, (uint8_t(*)[8])roundKeys, round);
  auto rhs_bits = extract_rhs_bits(roundKeys, ROUNDS[round].round_idx_pair);
  int rhs_xor = 0;
  for (int b : rhs_bits) rhs_xor ^= b;
  return rhs_xor;
}

PYBIND11_MODULE(helper, m) {
  m.def("test", &test);
  m.def("gen_dataset", &gen_dataset);
  m.def("set_seed", &set_seed);
  m.def("gen_key_cand_as_intdiff", &gen_key_cand_as_intdiff);
  m.def("printhex", &printhex);
  m.def("gen_pair_with_key", &gen_pair_with_key);
  m.def("extract_lhs", &extract_lhs);
  m.def("get_model_input_size", &get_model_input_size);
  m.def("check_rhs", &check_rhs);
}
