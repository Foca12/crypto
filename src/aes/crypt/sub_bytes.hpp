#pragma once

#include "../message.hpp"
#include "../helpers.hpp"

namespace crypt_operations
{
  Message sub_bytes(Message input){
    for (int i = 0; i < aes_constants::state_chars * input.length(); i++){
      input[i] = aes_constants::sbox[input[i]];
    }
    return input;
    }
  State sub_bytes(State input){
    for (int i = 0; i < aes_constants::state_chars; i++){
      input[i] = aes_constants::sbox[input[i]];
    }
    return input;
  }
  template <size_t len>
  aes_types::iarr<len> sub_bytes(aes_types::iarr<len> input){
    for (int i = 0; i < len; i++){
      input[i] = aes_constants::sbox[input[i]];
    }
    return input;
  }

  Message inv_sub_bytes(Message input){
    for (int i = 0; i < aes_constants::state_chars * input.length(); i++){
      input[i] = aes_constants::inv_sbox[input[i]];
    }
    return input;
    }
  State inv_sub_bytes(State input){
    for (int i = 0; i < aes_constants::state_chars; i++){
      input[i] = aes_constants::inv_sbox[input[i]];
    }
    return input;
  }
  template <size_t len>
  aes_types::iarr<len> inv_sub_bytes(aes_types::iarr<len> input){
    for (int i = 0; i < len; i++){
      input[i] = aes_constants::inv_sbox[input[i]];
    }
    return input;
  }
}