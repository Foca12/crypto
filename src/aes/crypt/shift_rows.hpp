#pragma once

#include "../helpers.hpp"
#include "../message.hpp"
#include "../state.hpp"

namespace crypt_operations
{
  State shift_rows(State input){
    for (size_t row_idx = 0; row_idx < aes_constants::state_rows; row_idx++){
      aes_types::state_row row = input.get_row(row_idx);
      row = aes_functions::shift_row_left(row, row_idx);
      input.set_row(row_idx, row);
    }
    return input;
  }
  Message shift_rows(Message input){
    for (size_t state_idx = 0; state_idx < input.length(); state_idx++){
      input.state(state_idx) = crypt_operations::shift_rows(input.state(state_idx));
    }
    return input;
  }

  State inv_shift_rows(State input){
    for (size_t row_idx = 0; row_idx < aes_constants::state_rows; row_idx++){
      aes_types::state_row row = input.get_row(row_idx);
      row = aes_functions::shift_row_right(row, row_idx);
      input.set_row(row_idx, row);
    }
    return input;
  }
  Message inv_shift_rows(Message input){
    for (size_t state_idx = 0; state_idx < input.length(); state_idx++){
      input.state(state_idx) = crypt_operations::inv_shift_rows(input.state(state_idx));
    }
    return input;
  }
}