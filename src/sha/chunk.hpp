#pragma once

#include "sha_helpers.hpp"
#include "../bytearray/bytearray.hpp"

namespace crypto::sha
{
  class Sha256_chunk{
    sha_types::sha256_word_list words = {};
    bool expanded = false;

    // helper function which calculate negative index
    size_t handle_idx(int idx) const {
      if (this->expanded){
        if (idx < 0){
          idx = sha_constants::sha256_n_rounds + idx;
        }
        if (idx > sha_constants::sha256_n_rounds){
          throw std::out_of_range("Chunk index exceeded words");
        }
      }
      else {
        if (idx < 0){
          idx = sha_constants::sha256_chunk_words + idx;
        }
        if (idx > sha_constants::sha256_chunk_words){
          throw std::out_of_range("Chunk index exceeded words");
        }
      }
      return idx;
    }
    

    // calculate a word for chunk expansion
    uint32_t calc_word(size_t word_idx) {
      uint32_t sigma1 = sha_functions::small_sigma1(this->words[word_idx-2]);
      uint32_t sigma0 = sha_functions::small_sigma0(this->words[word_idx-15]);

      return sigma1 + this->words[word_idx-7] + sigma0 + this->words[word_idx-16];
    }

    public:

    ~Sha256_chunk() {
      this->clear();
    }
  
    Sha256_chunk(const Bytearray& words){
      if (words.length() > sha_constants::sha256_chunk_words * 4){
        throw std::invalid_argument("Words length exceeded chunk dimension");
      }
      
      size_t acc = 3;
      size_t chunk_idx = 0;
      for (size_t idx = 0; idx < words.length(); idx++){
        this->words[chunk_idx] |= words[idx] << (8 * acc);

        if (acc == 0){
          acc = 4;
          chunk_idx++;
        }

        acc--;
      }
    }

    sha_types::sha256_word_list::iterator begin() {
      return this->words.begin();
    }
    sha_types::sha256_word_list::iterator end() {
      return this->expanded? this->words.end() : this->words.begin() + sha_constants::sha256_chunk_words;
    }
    sha_types::sha256_word_list::const_iterator begin() const {
      return this->words.begin();
    }
    sha_types::sha256_word_list::const_iterator end() const {
      return this->expanded? this->words.end() : this->words.begin() + sha_constants::sha256_chunk_words;
    }
  
    uint32_t& operator[](int idx){
      return this->words[this->handle_idx(idx)];
    }
    uint32_t operator[](int idx) const {
      return this->words[this->handle_idx(idx)];
    }
  
    bool is_expanded() {
      return this->expanded;
    }
    
    void clear() {
      volatile uint32_t* ptr = words.data();
      for (size_t i = 0; i < sha_constants::sha256_n_rounds; i++){
        ptr[i] = 0;
      }
      this->expanded = false;
    }
  
  
    void expand() {
      if (this->expanded){
        return;
      }

      this->expanded = true;

      for (size_t word_idx = sha_constants::sha256_chunk_words; word_idx < sha_constants::sha256_n_rounds; word_idx++){
        this->words[word_idx] = this->calc_word(word_idx);
      }
    }

    static Sha256_chunk from_hex(std::string words){
      return Sha256_chunk(Bytearray(sha_functions::basic_from_hex(words)));
    }
    static Sha256_chunk from_oct(std::string words){
      return Sha256_chunk(Bytearray(sha_functions::basic_from_oct(words)));
    }
  
    std::string hex() const {
      return sha_functions::basic_hex(this->words);
    }
    std::string oct() const {
      return sha_functions::basic_oct(this->words);
    }
  };

} // namespace crypto::sha
  
