#pragma once
#include <cstddef>
#include <array>

namespace DatabaseConstants {
  // ============================================================================================
  // ! POLY DEGREE = 2048
  // ============================================================================================

  // ! ========================== ~= 1GB database ==========================
  constexpr size_t PolyDegree = 2048;
  constexpr size_t TotalDims = 10;                   // total number of dimensions (d in paper)
  constexpr size_t GSW_L = 5;                       // parameter for GSW scheme
  constexpr size_t GSW_L_KEY = 15;                  // GSW for query expansion
  constexpr size_t FstDimSz = 512 - GSW_L * (TotalDims - 1); 
  constexpr size_t PlainMod = 17;
  constexpr size_t SmallQWidth = 27;                // modulus switching width
  constexpr std::array<size_t, 2> CoeffMods = {60, 61}; // log q = 60.

  // ============================================================================================
  // ! ==========================  POLY DEGREE = 4096 ==========================
  // ============================================================================================

  // ! ==========================  345MB (full expansion) ==========================
  // constexpr size_t PolyDegree = 4096;
  // constexpr size_t FstDimSz = 492;                  // 512 - l*(d-1) = 512 - 4*(6-1) = 512 - 20 = 492
  // constexpr size_t TotalDims = 6;                   // total number of dimensions (d in paper)
  // constexpr size_t GSW_L = 4;                       // parameter for GSW scheme
  // constexpr size_t GSW_L_KEY = 8;                   // GSW for query expansion
  // constexpr size_t PlainMod = 46;
  // constexpr size_t SmallQWidth = 57;                // modulus switching width
  // constexpr std::array<size_t, 3> CoeffMods = {60, 60, 60}; // log q = 60.


  // ============================================================================================
  // ! ==========================  special cases ==========================
  // ============================================================================================

  // ! ==========================  small entry(n=1024)==========================
  // constexpr size_t PolyDegree = 1024;
  // constexpr size_t TotalDims = 9;                  
  // constexpr size_t GSW_L = 10;            // RGSW parameter for external product in further dimension
  // constexpr size_t GSW_L_KEY = 20;        // used for RGSW(sk) in query expansion
  // constexpr size_t FstDimSz = 256 - GSW_L * (TotalDims - 1);        // 2^{tree_height} - l*(d-1)
  // constexpr size_t PlainMod = 4;
  // constexpr size_t SmallQWidth = 34;      // modulus switching width
  // constexpr std::array<size_t, 2> CoeffMods = { 34, 61 }; // 101-bit security


  // ! ==========================  small entry(n=1024)==========================
  // constexpr size_t PolyDegree = 1024;
  // constexpr size_t TotalDims = 10;                  
  // constexpr size_t GSW_L = 16;            // RGSW parameter for external product in further dimension
  // constexpr size_t GSW_L_KEY = 16;        // used for RGSW(sk) in query expansion
  // constexpr size_t PlainMod = 2;          // number of bits for plaintext modulus
  // constexpr size_t FstDimSz = 512 - GSW_L * (TotalDims - 1);        // 512 - l*(d-1)
  // constexpr size_t SmallQWidth = 32;     // modulus switching width
  // constexpr std::array<size_t, 2> CoeffMods = { 32, 61 }; // 107-bit security




  // ! ==========================  small entry 34-bit ct mods (n=1024)==========================
  // constexpr size_t MaxFstDimSz = 256;               // Maximum size of the first dimension. Actual size can only be smaller.
  // constexpr size_t PolyDegree = 1024;
  // constexpr size_t NumEntries = 1 << 15;            // number of entries in the database
  // constexpr size_t GSW_L = 20;                      // parameter for GSW scheme
  // constexpr size_t GSW_L_KEY = 20;                  // GSW for query expansion
  // constexpr size_t PlainMod = 5;
  // constexpr size_t SmallQWidth = 34;                // modulus switching width.
  // constexpr std::array<size_t, 2> CoeffMods = { 34, 61 };

  // ! ==========================  small entry 32-bit ct mods (n=1024)==========================
  // constexpr size_t MaxFstDimSz = 128;               // Maximum size of the first dimension. Actual size can only be smaller.
  // constexpr size_t PolyDegree = 1024;
  // constexpr size_t NumEntries = 1 << 15;            // number of entries in the database
  // constexpr size_t GSW_L = 28;                      // parameter for GSW scheme
  // constexpr size_t GSW_L_KEY = 28;                  // GSW for query expansion
  // constexpr size_t PlainMod = 3;
  // constexpr size_t SmallQWidth = 32;                // modulus switching width.
  // constexpr std::array<size_t, 2> CoeffMods = { 32, 61 };

} // namespace DatabaseConstants