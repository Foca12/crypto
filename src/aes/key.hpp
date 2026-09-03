#pragma once

#include "aes_helpers.hpp"
#include "crypt/sub_bytes.hpp"

namespace crypto::aes
{
class Key {
  private:
  static Bytearray g(Bytearray x, size_t round) {
    x = x.shift_left(1);
    x = crypt_operations::sub_bytes(x);
    x[0] ^= aes_constants::rcon[round];
    return x;
  }

  
  static Bytearray calc_key128_word(const aes_types::word_list& words, size_t word_idx){
    if (word_idx < 4){
      return words[word_idx];
    }

    Bytearray a = words[word_idx-1];
    Bytearray b = words[word_idx-4];
    if (word_idx % 4 == 0){
      a = Key::g(a, word_idx / 4);
    }
    return a ^ b;
  }

  static Bytearray calc_key192_word(const aes_types::word_list& words, size_t word_idx){
    if (word_idx < 6){
      return words[word_idx];
    }

    Bytearray a = words[word_idx-1];
    Bytearray b = words[word_idx-6];

    if (word_idx % 6 == 0){
      a = Key::g(a, word_idx / 6);
    }

    return a ^ b;
  }

  static Bytearray calc_key256_word(const aes_types::word_list& words, size_t word_idx){
    if (word_idx < 8) {
      return words[word_idx];
    }

    Bytearray a = words[word_idx-1];
    Bytearray b = words[word_idx-8];

    if (word_idx % 8 == 0){
      a = Key::g(a, word_idx / 8);
    }
    else if (word_idx % 4 == 0){
      a = crypt_operations::sub_bytes(a);
    }

    return a ^ b;
  }


  struct key_spec
  {
    size_t chars, start_words, total_words, total_rounds;
    Bytearray (* calc_word)(const aes_types::word_list&, size_t);
  };
  
  // contains aes128, aes192 and aes256
  static constexpr std::array<key_spec, 3> global_key_specs = {
    Key::key_spec{
      aes_constants::key128_chars,
      aes_constants::key128_start_words,
      aes_constants::key128_total_words,
      aes_constants::key128_rounds,
      &Key::calc_key128_word},

    Key::key_spec{
      aes_constants::key192_chars,
      aes_constants::key192_start_words,
      aes_constants::key192_total_words,
      aes_constants::key192_rounds,
      &Key::calc_key192_word},

    Key::key_spec{
      aes_constants::key256_chars,
      aes_constants::key256_start_words,
      aes_constants::key256_total_words,
      aes_constants::key256_rounds,
      &Key::calc_key256_word},
  };
  
  aes_types::word_list words = {};
  Key::key_spec key_specs;
  bool expanded = false;

  public:
  ~Key() {
    this->clear();
  }
  Key (const Bytearray& bytes){
    for (auto& key_spec : Key::global_key_specs){
      // if input length matches with a key length
      if (bytes.size() == key_spec.chars){
        this->key_specs = key_spec;
        this->words.reserve(key_spec.total_words);

        // iterates through bytes, divide it into word array and pushes them in this->bytes
        for (size_t word_idx = 0; word_idx < key_spec.start_words; word_idx++){
          size_t start_bias = word_idx*aes_constants::state_rows;
          size_t end_bias = (word_idx+1)*aes_constants::state_rows;

          Bytearray word = bytes.slice(start_bias, end_bias);
          this->words.push_back(word);
        }
        return;
      }
    }
    throw std::invalid_argument("Invalid key length");
  }

  void clear(){
    for (Bytearray& word : this->words){
      word.clear();
    }
  }

  void expand() {
    if (this->expanded){
      return;
    }
    this->expanded = true;

    for (size_t i = this->key_specs.start_words; i < this->key_specs.total_words; i++){
      // uses the key_specs.calc_word function ptr to calculate new word
      this->words.push_back((*(this->key_specs.calc_word))(this->words, i));
    }
  }

  const aes_types::word_list& get_words() const {
    return this->words;
  }
  const Key::key_spec& get_specs() const {
    return this->key_specs;
  }
  bool is_expanded() const {
    return this->expanded;
  }

  static Key from_hex(const std::string& str){
    return Key(aes_functions::basic_from_hex(str));
  }
  static Key from_oct(const std::string& str){
    return Key(aes_functions::basic_from_oct(str));
  }

  std::string hex(bool all_keys=0) const {
    Bytearray arr;
    size_t end_idx = all_keys? this->key_specs.total_words : this->key_specs.start_words;
    for (size_t i = 0; i < end_idx; i++){
      arr.extend(this->words[i]);
    }
    return arr.hex();
  }
  std::string oct(bool all_keys=0) const {
    Bytearray arr;
    size_t end_idx = all_keys? this->key_specs.total_words : this->key_specs.start_words;
    for (size_t i = 0; i < end_idx; i++){
      arr.extend(this->words[i]);
    }
    return arr.oct();
  }
};
}