#pragma once

#include "../aes_helpers.hpp"
#include "../message.hpp"
#include "../state.hpp"

namespace crypto::aes::crypt_operations
{
  State shift_rows(State input){
    for (size_t row_idx = 0; row_idx < aes_constants::state_rows; row_idx++){
      Bytearray row = input.get_row(row_idx).shift_left(row_idx);
      input.set_row(row_idx, row);
    }
    return input;
  }
  Message shift_rows(Message input){
    for (State& state : input.state_iterator()){
      state = crypt_operations::shift_rows(state);
    }
    return input;
  }


  State inv_shift_rows(State input){
    for (size_t row_idx = 0; row_idx < aes_constants::state_rows; row_idx++){
      Bytearray row = input.get_row(row_idx).shift_right(row_idx);
      input.set_row(row_idx, row);
    }
    return input;
  }
  Message inv_shift_rows(Message input){
    for (State& state : input.state_iterator()){
      state = crypt_operations::inv_shift_rows(state);
    }
    return input;
  }
}