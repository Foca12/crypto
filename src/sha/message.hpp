#pragma once

#include "chunk.hpp"
#include "sha_helpers.hpp"

namespace crypto::sha
{
  class Sha256_message{
    sha_types::sha256_chunk_list chunks;

    struct chunk_support_iterator {
      sha_types::sha256_chunk_list& chunks;

      sha_types::sha256_chunk_list::iterator begin() {
        return this->chunks.begin();
      }
      sha_types::sha256_chunk_list::iterator end() {
        return this->chunks.end();
      }
      sha_types::sha256_chunk_list::const_iterator begin() const {
        return this->chunks.begin();
      }
      sha_types::sha256_chunk_list::const_iterator end() const {
        return this->chunks.end();
      }
    };

    // helper function which calculate negative index for message.chunk
    size_t handle_chunk_idx(int idx){
      return idx < 0? this->length() + idx : idx;
    }

    public:

    Sha256_message(const sha_types::sha256_chunk_list& chunks){
      this->chunks = chunks;
    }

    static Sha256_message divide_bytearray(Bytearray bytes){      
      auto ceil_division = [](size_t a, size_t b) -> size_t {return ((a+b-1)/b);};
      
      size_t bit_length = bytes.length() * 8; // length of bytes expressed in bits
      bytes.push_back(0x80);

      sha_types::sha256_chunk_list chunks; // chunks
      size_t total_occupied_words = ceil_division(bytes.length(), 4);
      size_t last_occupied_words = total_occupied_words % sha_constants::sha256_chunk_words;
      size_t occupied_chunks = total_occupied_words / sha_constants::sha256_chunk_words;

      // make bytes a multiple of 4
      size_t bytes_to_add = total_occupied_words * 4 - bytes.length();
      bytes.extend(Bytearray(bytes_to_add));

      // foreach full chunk pushes the chunk into the vector
      for (size_t chunk_idx = 0; chunk_idx < occupied_chunks; chunk_idx++){
        size_t start_idx = chunk_idx*sha_constants::sha256_chunk_words*4;
        size_t end_idx = (chunk_idx+1)*sha_constants::sha256_chunk_words*4;
        Sha256_chunk current_chunk = Sha256_chunk(bytes.slice(start_idx, end_idx));
        chunks.push_back(current_chunk);
      }

      // last chunk
      size_t start = occupied_chunks * 4 * sha_constants::sha256_chunk_words;
      Bytearray last_slice = bytes.slice(start, bytes.length());
      // if last chunk can contain the start message length (2 words)
      if (sha_constants::sha256_chunk_words - (last_slice.length() / 4) >= sha_constants::sha256_padding_length_size){
        size_t padding_needed = sha_constants::sha256_chunk_words * 4 - last_slice.length();
        last_slice.extend(Bytearray(padding_needed));

        Sha256_chunk last_chunk(last_slice);
        last_chunk[-2] = static_cast<uint32_t> (bit_length >> 32);
        last_chunk[-1] = static_cast<uint32_t> (bit_length << 32 >> 32);

        chunks.push_back(last_chunk);
      }
      else {
        size_t padding_needed = sha_constants::sha256_chunk_words * 4 - last_slice.length();
        last_slice.extend(Bytearray(padding_needed));
        chunks.push_back(Sha256_chunk(last_slice));

        Sha256_chunk last_chunk(Bytearray(sha_constants::sha256_chunk_words * 4));
        last_chunk[-2] = static_cast<uint32_t> (bit_length >> 32);
        last_chunk[-1] = static_cast<uint32_t> (bit_length << 32 >> 32);

        chunks.push_back(last_chunk);
      }

      return Sha256_message(chunks);
    }

    void expand() {
      for (Sha256_chunk& chunk : this->chunks){
        chunk.expand();
      }
    }

    Sha256_chunk& chunk(size_t index) {
      return this->chunks[this->handle_chunk_idx(index)];
    }
    const Sha256_chunk& chunk(size_t index) const {
      return this->chunks[index];
    }

    Sha256_message::chunk_support_iterator chunk_iterator() {
      return Sha256_message::chunk_support_iterator(this->chunks);
    }

    sha_types::sha256_word_list::iterator begin() {
      return this->chunk(0).begin();
    }
    sha_types::sha256_word_list::iterator end() {
      return this->chunk(-1).end();
    }
    sha_types::sha256_word_list::const_iterator begin() const {
      return this->chunk(0).begin();
    }
    sha_types::sha256_word_list::const_iterator end() const {
      return this->chunk(-1).end();
    }

    size_t length() const {
      return this->chunks.size();
    }
    size_t size() const {
      return this->chunks.size();
    }

    static Sha256_message from_hex(std::string str) {
      return Sha256_message::divide_bytearray(Bytearray::from_hex(str));
    }
    static Sha256_message from_oct(std::string str) {
      return Sha256_message::divide_bytearray(Bytearray::from_oct(str));
    }

    std::string hex() const {
      std::string str;
      for (const auto& i : this->chunks){
        str += i.hex();
      }
      return str;
    }
    std::string oct() const {
      std::string str;
      for (const auto& i : this->chunks){
        str += i.oct();
      }
      return str;
    }
  };
} // namespace crypto::sha
