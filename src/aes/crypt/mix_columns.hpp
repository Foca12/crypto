#pragma once

#include "../aes_helpers.hpp"
#include "../state.hpp"
#include "../message.hpp"

namespace crypt_operations
{ 
  Bytearray basic_mix_columns(
      Bytearray column, 
      const std::function<uint8_t(uint8_t)> matrix[aes_constants::state_rows][aes_constants::state_rows]){

    Bytearray result;

    // foreach element in the column
    for (size_t result_idx = 0; result_idx < aes_constants::state_rows; result_idx++){
      uint8_t sum = 0;
      // calculate the xor-weighted-sum of all column elements
      for (size_t mul_idx = 0; mul_idx < aes_constants::state_rows; mul_idx++){
        sum ^= matrix[result_idx][mul_idx](column[mul_idx]);
      }
      result.push_back(sum);
    }
    return result;
  }

  Bytearray mix_columns(Bytearray column){
    return basic_mix_columns(column, aes_functions::mul_matrix);
  }
  State mix_columns(State state){
    State result;
    for (size_t i = 0; i < aes_constants::state_columns; i++){
      result.set_column(i, mix_columns(state.get_column(i)));
    }
    return result;
  }
  Message mix_columns(Message message){
    for (State& state : message.state_iterator()){
      state = crypt_operations::mix_columns(state);
    }
    return message;
  }


  Bytearray inv_mix_columns(Bytearray column){
    return basic_mix_columns(column, aes_functions::inv_mul_matrix);
  }
  State inv_mix_columns(State state){
    State result;
    for (size_t i = 0; i < aes_constants::state_columns; i++){
      result.set_column(i, inv_mix_columns(state.get_column(i)));
    }
    return result;
  }
  Message inv_mix_columns(Message message){
    for (State& state : message.state_iterator()){
      state = crypt_operations::inv_mix_columns(state);
    }
    return message;
  }
}