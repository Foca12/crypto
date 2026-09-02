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
#include <array>
#include <ranges>

class State;
namespace crypto_types
{
  // general types
  template <size_t len>
  using iarr = std::array<uint8_t, len>;
  using ilist = std::vector<uint8_t>;

  using ilist_c_iterator = typename crypto_types::ilist::const_iterator;
  using ilist_iterator = typename crypto_types::ilist::iterator;

  template <size_t len>
  using iarr_c_iterator = typename crypto_types::iarr<len>::const_iterator;
  template <size_t len>
  using iarr_iterator = typename crypto_types::iarr<len>::iterator;
} // namespace crypto_types


namespace crypto_functions
{
  std::string convert_to_string(const crypto_types::ilist& vct){  
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
  std::string convert_to_string(const crypto_types::iarr<len>& arr){  
    crypto_types::ilist vct;
    vct.assign(arr.begin(), arr.end());
    return convert_to_string(vct);
  }

  // convert hex/oct string in vector of uint
  crypto_types::ilist basic_from_hex(const std::string& str){  
    if (str.length() % 2 != 0){
      throw std::invalid_argument("Invalid hex number");
    }

    crypto_types::ilist vct;
    for (size_t i = 0; i < str.length(); i += 2){
      std::string tmp = str.substr(i, 2);
      vct.push_back(std::stoi(tmp, nullptr, 16));
    }
    return vct;
  }
  crypto_types::ilist basic_from_oct(const std::string& str){  
    if (str.length() % 3 != 0){
      throw std::invalid_argument("Invalid oct number");
    }

    crypto_types::ilist vct;
    for (size_t i = 0; i < str.length(); i += 3){
      std::string tmp = str.substr(i, 3);
      vct.push_back(std::stoi(tmp, nullptr, 8));
    }
    return vct;
  }
  // convert vector of uint in hex/oct string
  std::string basic_hex(const crypto_types::ilist& bytes){  
    std::stringstream ss;
    
    for (const int& i : bytes) {
      ss << std::hex << std::setw(2) << std::setfill('0') << i;
    }

    return ss.str();
  }
  std::string basic_oct(const crypto_types::ilist& bytes){  
    std::stringstream ss;
    
    for (const int& i : bytes) {
      ss << std::oct << std::setw(3) << std::setfill('0') << i;
    }

    return ss.str();
  }
  template <size_t len>
  std::string basic_hex(crypto_types::iarr<len> bytes){
    crypto_types::ilist vct;
    vct.assign(bytes.begin(), bytes.end());
    return crypto_functions::basic_hex(vct);
  }
  template <size_t len>
  std::string basic_oct(crypto_types::iarr<len> bytes){
    crypto_types::ilist vct;
    vct.assign(bytes.begin(), bytes.end());
    return crypto_functions::basic_oct(vct);
  }
} // namespace crypto_functions