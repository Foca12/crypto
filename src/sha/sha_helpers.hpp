#pragma once

#include <cstddef>
#include <cstdint>
#include <sstream>
#include <stdexcept>
#include <iomanip>
#include <vector>
#include <string>
#include <functional>
#include <algorithm>
#include <cmath>
#include <cstring>
#include <array>
#include <bit>

namespace crypto::sha
{
  class Sha256_chunk;

  namespace sha_constants
  {
    constexpr size_t sha256_n_rounds = 64;

    constexpr size_t sha256_chunk_words = 16;

    constexpr size_t sha256_padding_length_size = 2;

    constexpr size_t n_hashes = 8;

    constexpr std::array<uint32_t, sha_constants::n_hashes> sha256_start_hashes = {
      0x6a09e667,
      0xbb67ae85,
      0x3c6ef372,
      0xa54ff53a,
      0x510e527f,
      0x9b05688c,
      0x1f83d9ab,
      0x5be0cd19
    };
  
    constexpr std::array<uint32_t, sha256_n_rounds> sha256_k = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
  } // namespace sha_constants
  
  namespace sha_types
  {
    using ilist = std::vector<uint32_t>;
    using ilist_c_iterator = typename ilist::const_iterator;
    using ilist_iterator = typename ilist::iterator;

    template <size_t len>
    using iarr = std::array<uint32_t, len>;

    template <size_t len>
    using iarr_c_iterator = typename iarr<len>::const_iterator;
    template <size_t len>
    using iarr_iterator = typename iarr<len>::iterator;
    

    using sha256_word_list = iarr<sha_constants::sha256_n_rounds>;
    using sha256_chunk_list = std::vector<Sha256_chunk>;
    using sha256_hash_array = std::array<uint32_t, sha_constants::n_hashes>;
  } // namespace sha_types
  
  namespace sha_functions
  {
    std::string convert_to_string(const sha_types::ilist& vct){  
      std::stringstream ss;
      std::string str;
      bool only_valid = true;
    
      for (const uint8_t& i : vct) {
        // if its out of range of ASCII chars
        if (i < 32 || i > 126){
          only_valid = false;
        }
        if (only_valid){
          str += static_cast<char>(i);
        }
        ss << "\\x";
        ss << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(i);
      }
    
      return only_valid? str : ss.str();
    }
    template <size_t len>
    std::string convert_to_string(const sha_types::iarr<len>& arr){  
      sha_types::ilist vct;
      vct.assign(arr.begin(), arr.end());
      return convert_to_string(vct);
    }

    // convert hex/oct string in vector of uint
    sha_types::ilist basic_from_hex(const std::string& str){  
      if (str.length() % 8 != 0){
        throw std::invalid_argument("Invalid hex number");
      }
    
      sha_types::ilist vct;
      for (size_t i = 0; i < str.length(); i += 2){
        std::string tmp = str.substr(i, 2);
        vct.push_back(std::stoi(tmp, nullptr, 16));
      }
      return vct;
    }
    sha_types::ilist basic_from_oct(const std::string& str){  
      if (str.length() % 12 != 0){
        throw std::invalid_argument("Invalid oct number");
      }
    
      sha_types::ilist vct;
      for (size_t i = 0; i < str.length(); i += 3){
        std::string tmp = str.substr(i, 3);
        vct.push_back(std::stoi(tmp, nullptr, 8));
      }
      return vct;
    }
    // convert vector of uint in hex/oct string
    std::string basic_hex(const sha_types::ilist& bytes){  
      std::stringstream ss;

      for (const int& i : bytes) {
        ss << std::hex << std::setw(8) << std::setfill('0') << i;
      }
    
      return ss.str();
    }
    std::string basic_oct(const sha_types::ilist& bytes){  
      std::stringstream ss;

      for (const int& i : bytes) {
        ss << std::oct << std::setw(12) << std::setfill('0') << i;
      }
    
      return ss.str();
    }
    template <size_t len>
    std::string basic_hex(sha_types::iarr<len> bytes){
      sha_types::ilist vct;
      vct.assign(bytes.begin(), bytes.end());
      return sha_functions::basic_hex(vct);
    }
    template <size_t len>
    std::string basic_oct(sha_types::iarr<len> bytes){
      sha_types::ilist vct;
      vct.assign(bytes.begin(), bytes.end());
      return sha_functions::basic_oct(vct);
    }
  
    uint32_t small_sigma0(uint32_t x) {
      return std::rotr(x, 7) ^ std::rotr(x, 18) ^ (x >> 3);
    }
    uint32_t small_sigma1(uint32_t x) {
      return std::rotr(x, 17) ^ std::rotr(x, 19) ^ (x >> 10);
    }
    uint32_t big_sigma0(uint32_t x) {
      return std::rotr(x, 2) ^ std::rotr(x, 13) ^ std::rotr(x, 22);
    }
    uint32_t big_sigma1(uint32_t x) {
      return std::rotr(x, 6) ^ std::rotr(x, 11) ^ std::rotr(x, 25);
    }

    uint32_t ch(uint32_t x, uint32_t y, uint32_t z){
      return (x & y) | (~x & z);
    }
    uint32_t maj(uint32_t x, uint32_t y, uint32_t z){
      return (x & y) | (y & z) | (x & z);
    }
  
    template <typename collection>
    requires std::ranges::contiguous_range<collection>
    uint32_t calc_t1(size_t round, const sha_types::sha256_hash_array& hashes, const collection& chunk){
      return hashes[7] + sha_functions::big_sigma1(hashes[4]) + sha_functions::ch(hashes[4], hashes[5], hashes[6]) + sha_constants::sha256_k[round] + chunk[round];
    }
    uint32_t calc_t2(size_t round, const sha_types::sha256_hash_array& hashes){
      return sha_functions::big_sigma0(hashes[0]) + sha_functions::maj(hashes[0], hashes[1], hashes[2]);
    }
  
    void cicle_hashes(sha_types::sha256_hash_array& hashes, uint32_t t1, uint32_t t2){
      hashes[7] = hashes[6];
      hashes[6] = hashes[5];
      hashes[5] = hashes[4];
      hashes[4] = hashes[3] + t1;
      hashes[3] = hashes[2];
      hashes[2] = hashes[1];
      hashes[1] = hashes[0];
      hashes[0] = t1 + t2;
    }
  }
} // namespace crypto
