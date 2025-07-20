#pragma once
#include <cstddef>
#include <array>

namespace DatabaseConstants {
  // Currently, if the degree is 4096, 256 for the first dimension looks optimal. 
  // If the degree is 2048, 512 for the first dimension looks optimal.

  // ============================================================================================
  // ! THE FOLLOWING FEW CHOICES ARE FOR POLYNOMIAL DEGREE = 4096
  // ============================================================================================

  // ! ========================== 11.25GB (best throughput) ==========================
  // constexpr size_t PolyDegree = 4096;
  // constexpr size_t FstDimSz = 512;                   // manually set N_0
  // constexpr size_t TotalDims = 11;                   // total number of dimensions (d in paper)
  // constexpr size_t EntrySize = 0;                    // 0 means calculated automatically. Take the largest possible value.
  // constexpr size_t GSW_L = 4;                        // parameter for GSW scheme
  // constexpr size_t GSW_L_KEY = 8;                    // GSW for query expansion
  // constexpr size_t PlainMod = 46;
  // constexpr size_t SmallQWidth = 57;                 // modulus switching width
  // constexpr std::array<size_t, 3> CoeffMods = {60, 60, 60}; // log q = 60.


  // ! ========================== 1.4GB ==========================
  // constexpr size_t PolyDegree = 4096;
  // constexpr size_t FstDimSz = 512;                  // manually set N_0
  // constexpr size_t TotalDims = 8;                   // total number of dimensions (d in paper)
  // constexpr size_t EntrySize = 0;                   // 0 means calculated automatically. Take the largest possible value.
  // constexpr size_t GSW_L = 4;                       // parameter for GSW scheme
  // constexpr size_t GSW_L_KEY = 8;                   // GSW for query expansion
  // constexpr size_t PlainMod = 46;
  // constexpr size_t SmallQWidth = 57;                // modulus switching width
  // constexpr std::array<size_t, 3> CoeffMods = {60, 60, 60}; // log q = 60.



  // ============================================================================================
  // ! THE FOLLOWING FEW CHOICES ARE FOR POLYNOMIAL DEGREE = 2048
  // ============================================================================================

  // ! ========================== 2^21 * 4KB = 8GB (best throughput) ==========================
  // constexpr size_t PolyDegree = 2048;
  // constexpr size_t FstDimSz = 512;                  // manually set N_0
  // constexpr size_t TotalDims = 13;                  // total number of dimensions (d in paper)
  // constexpr size_t EntrySize = 0;                   // 0 means calculated automatically. Take the largest possible value.
  // constexpr size_t GSW_L = 5;                       // parameter for GSW scheme
  // constexpr size_t GSW_L_KEY = 10;                  // GSW for query expansion
  // constexpr size_t PlainMod = 17;
  // constexpr size_t SmallQWidth = 27;                // modulus switching width
  // constexpr std::array<size_t, 2> CoeffMods = {60, 60}; // log q = 60.

  // ! ========================== 1GB ==========================
  // constexpr size_t PolyDegree = 2048;
  // constexpr size_t FstDimSz = 512;                  // manually set N_0
  // constexpr size_t TotalDims = 10;                  // total number of dimensions (d in paper)
  // constexpr size_t EntrySize = 0;                   // 0 means calculated automatically. Take the largest possible value.
  // constexpr size_t GSW_L = 5;                       // parameter for GSW scheme
  // constexpr size_t GSW_L_KEY = 10;                  // GSW for query expansion
  // constexpr size_t PlainMod = 17;
  // constexpr size_t SmallQWidth = 27;                // modulus switching width
  // constexpr std::array<size_t, 2> CoeffMods = {60, 60}; // log q = 60.

  // ! ========================== 256MB ==========================
  // constexpr size_t PolyDegree = 2048;
  // constexpr size_t FstDimSz = 512;                  // manually set N_0
  // constexpr size_t TotalDims = 8;                   // total number of dimensions (d in paper)
  // constexpr size_t EntrySize = 0;                   // 0 means calculated automatically. Take the largest possible value.
  // constexpr size_t GSW_L = 5;                       // parameter for GSW scheme
  // constexpr size_t GSW_L_KEY = 10;                  // GSW for query expansion
  // constexpr size_t PlainMod = 17;
  // constexpr size_t SmallQWidth = 27;                // modulus switching width
  // constexpr std::array<size_t, 2> CoeffMods = {60, 60}; // log q = 60.

  // ! ========================== 256MB (1KB) ==========================
  // constexpr size_t PolyDegree = 2048;
  // constexpr size_t FstDimSz = 512;                  // manually set N_0
  // constexpr size_t TotalDims = 8;                   // total number of dimensions (d in paper)
  // constexpr size_t EntrySize = 1024;                // 0 means calculated automatically. Take the largest possible value.
  // constexpr size_t GSW_L = 5;                       // parameter for GSW scheme
  // constexpr size_t GSW_L_KEY = 10;                  // GSW for query expansion
  // constexpr size_t PlainMod = 17;
  // constexpr size_t SmallQWidth = 27;                // modulus switching width
  // constexpr std::array<size_t, 2> CoeffMods = {60, 60}; // log q = 60.




  // ============================================================================================
  // ! DEMO FOR FULL EXPANSION TREE PARAMS
  // ============================================================================================

  // ! ========================== 238.5MB (full expansion) ==========================
  // constexpr size_t PolyDegree = 2048;
  // constexpr size_t FstDimSz = 477;                  // 512 - l*(d-1) = 512 - 5*(8-1) = 512 - 35 = 477
  // constexpr size_t TotalDims = 8;                   // total number of dimensions (d in paper)
  // constexpr size_t EntrySize = 0;                   // 0 means calculated automatically. Take the largest possible value.
  // constexpr size_t GSW_L = 5;                       // parameter for GSW scheme
  // constexpr size_t GSW_L_KEY = 10;                  // GSW for query expansion
  // constexpr size_t PlainMod = 17;
  // constexpr size_t SmallQWidth = 27;                // modulus switching width
  // constexpr std::array<size_t, 2> CoeffMods = {60, 60}; // log q = 60.

  // ! ========================== 1848MB (full expansion) ==========================
  // constexpr size_t PolyDegree = 2048;
  // constexpr size_t FstDimSz = 462;                  // 512 - l*(d-1) = 512 - 5*(11-1) = 512 - 50 = 462
  // constexpr size_t TotalDims = 11;                  // total number of dimensions (d in paper)
  // constexpr size_t EntrySize = 0;                   // 0 means calculated automatically. Take the largest possible value.
  // constexpr size_t GSW_L = 5;                       // parameter for GSW scheme
  // constexpr size_t GSW_L_KEY = 10;                  // GSW for query expansion
  // constexpr size_t PlainMod = 17;
  // constexpr size_t SmallQWidth = 27;                // modulus switching width
  // constexpr std::array<size_t, 2> CoeffMods = {60, 60}; // log q = 60.


  // ! ==========================  345MB (full expansion) ==========================
  // constexpr size_t PolyDegree = 4096;
  // constexpr size_t FstDimSz = 492;                  // 512 - l*(d-1) = 512 - 4*(6-1) = 512 - 20 = 492
  // constexpr size_t TotalDims = 6;                   // total number of dimensions (d in paper)
  // constexpr size_t EntrySize = 0;                   // 0 means calculated automatically. Take the largest possible value.
  // constexpr size_t GSW_L = 4;                       // parameter for GSW scheme
  // constexpr size_t GSW_L_KEY = 8;                   // GSW for query expansion
  // constexpr size_t PlainMod = 46;
  // constexpr size_t SmallQWidth = 57;                // modulus switching width
  // constexpr std::array<size_t, 3> CoeffMods = {60, 60, 60}; // log q = 60.


  // ! ==========================  small entry(n=1024)==========================
  constexpr size_t PolyDegree = 1024;
  constexpr size_t TotalDims = 9;                  
  constexpr size_t EntrySize = 0;         // 0 means calculated automatically. Take the largest possible value.
  constexpr size_t GSW_L = 10;            // RGSW parameter for external product in further dimension
  constexpr size_t GSW_L_KEY = 20;        // used for RGSW(sk) in query expansion
  constexpr size_t FstDimSz = 256 - GSW_L * (TotalDims - 1);        // 2^{tree_height} - l*(d-1)
  constexpr size_t PlainMod = 4;
  constexpr size_t SmallQWidth = 34;      // modulus switching width
  constexpr std::array<size_t, 2> CoeffMods = { 34, 61 }; // 101-bit security


  // ! ==========================  small entry(n=1024)==========================
  // constexpr size_t PolyDegree = 1024;
  // constexpr size_t TotalDims = 10;                  
  // constexpr size_t EntrySize = 0;         // 0 means calculated automatically. Take the largest possible value.
  // constexpr size_t GSW_L = 16;            // RGSW parameter for external product in further dimension
  // constexpr size_t GSW_L_KEY = 16;        // used for RGSW(sk) in query expansion
  // constexpr size_t PlainMod = 2;          // number of bits for plaintext modulus
  // constexpr size_t FstDimSz = 512 - GSW_L * (TotalDims - 1);        // 512 - l*(d-1)
  // constexpr size_t SmallQWidth = 32;     // modulus switching width
  // constexpr std::array<size_t, 2> CoeffMods = { 32, 61 }; // 107-bit security


} // namespace DatabaseConstants