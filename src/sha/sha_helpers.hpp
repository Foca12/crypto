#pragma once

#include <array>
#include "../helpers.hpp"

namespace sha_constants
{
  namespace sha256
  {
    constexpr size_t words = 16;
    constexpr size_t word_chars = 32;
    
    constexpr size_t n_vars = 8;
    constexpr std::array<uint32_t, sha256::n_vars> vars = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    };


  } // namespace sha256
  
} // namespace sha_constants

namespace sha_functions
{
  uint32_t rotr(uint32_t x, size_t times){
    return x << sizeof(uint32_t)*CHAR_BIT-times | x >> times;
  }

  template <typename T>
  requires std::same_as<T, uint32_t> || std::same_as<T, uint64_t>
  T ch(T x, T y, T z){
    return (x & y) ^ (~x & z);
  }
  template <typename T>
  requires std::same_as<T, uint32_t> || std::same_as<T, uint64_t>
  T Maj(T x, T y, T z){
    return (x & y) ^ (x & z) ^ (y & z)
  }

  namespace sha256
  {
    
    uint32_t sigma0(uint32_t x){
      return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }
    uint32_t sigma1(uint32_t x){
      return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }

    uint32_t diff0(uint32_t x){
      return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }
    uint32_t diff1(uint32_t x){
      return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }
  } // namespace sha256
} // namespace sha_functions
