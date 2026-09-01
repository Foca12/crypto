#pragma once

#include "../message.hpp"
#include "../../bytearray.hpp"
#include "../aes_helpers.hpp"

namespace crypt_operations
{
  Message sub_bytes(Message input){
    for (size_t i = 0; i < aes_constants::state_chars * input.length(); i++){
      input[i] = aes_constants::sbox[input[i]];
    }
    return input;
    }
  State sub_bytes(State input){
    for (size_t i = 0; i < aes_constants::state_chars; i++){
      input[i] = aes_constants::sbox[input[i]];
    }
    return input;
  }
  Bytearray sub_bytes(Bytearray input){
    for (size_t i = 0; i < input.length(); i++){
      input[i] = aes_constants::sbox[input[i]];
    }
    return input;
  }

  Message inv_sub_bytes(Message input){
    for (size_t i = 0; i < aes_constants::state_chars * input.length(); i++){
      input[i] = aes_constants::inv_sbox[input[i]];
    }
    return input;
    }
  State inv_sub_bytes(State input){
    for (size_t i = 0; i < aes_constants::state_chars; i++){
      input[i] = aes_constants::inv_sbox[input[i]];
    }
    return input;
  }
  Bytearray inv_sub_bytes(Bytearray input){
    for (size_t i = 0; i < input.length(); i++){
      input[i] = aes_constants::inv_sbox[input[i]];
    }
    return input;
  }
}