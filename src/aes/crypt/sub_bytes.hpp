#pragma once

#include "../message.hpp"
#include "../aes_helpers.hpp"

namespace crypt_operations
{
  Bytearray sub_bytes(Bytearray input){
    for (size_t i = 0; i < input.length(); i++){
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
  Message sub_bytes(Message input){
    for (State& state : input.state_iterator()){
      state = crypt_operations::sub_bytes(state);
    }
    return input;
  }
  
  
  Bytearray inv_sub_bytes(Bytearray input){
    for (size_t i = 0; i < input.length(); i++){
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
  Message inv_sub_bytes(Message input){
    for (State& state : input.state_iterator()){
      state = crypt_operations::inv_sub_bytes(state);
    }
    return input;
    }
}