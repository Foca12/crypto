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

namespace crypto::sha
{
  class Sha256_chunk;

  namespace sha_constants
  {
    constexpr size_t sha256_n_rounds = 64;

    constexpr size_t sha256_chunk_words = 16;

    constexpr size_t sha256_padding_length_size = 2;

    constexpr std::array<uint32_t, 8> sha256_start_ashes = {
          0x6a09e667,
          0xbb67ae85,
          0x3c6ef372,
          0xa54ff53a,
          0x9b05688c,
          0x1f83d9ab,
          0x5be0cd19
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
  

    uint32_t rotr(uint32_t x, size_t times){
      return (x << (sizeof(x) * CHAR_BIT - times)) | (x >> times);
    }
  
    uint32_t small_sigma0(uint32_t x) {
      return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }
    uint32_t small_sigma1(uint32_t x) {
      return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }
    uint32_t big_sigma0(uint32_t x) {
      return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }
    uint32_t big_sigma1(uint32_t x) {
      return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }

    uint32_t ch(uint32_t x, uint32_t y, uint32_t z){
      return (x & y) | (~x & z);
    }
    uint32_t maj(uint32_t x, uint32_t y, uint32_t z){
      return (x & y) | (y & z) | (x & z);
    }
  }
} // namespace crypto
