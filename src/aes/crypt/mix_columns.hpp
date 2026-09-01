#pragma once

#include "../helpers.hpp"

namespace crypt_operations
{ 
  aes_types::state_column basic_mix_columns(
      aes_types::state_column column, 
      const std::function<uint8_t(uint8_t)> matrix[aes_constants::state_rows][aes_constants::state_rows]){

    aes_types::state_column result;

    // foreach element in the column
    for (size_t result_idx = 0; result_idx < aes_constants::state_rows; result_idx++){
      uint8_t sum = 0;
      // calculate the xor-weighted-sum of all column elements
      for (size_t mul_idx = 0; mul_idx < aes_constants::state_rows; mul_idx++){
        sum ^= matrix[result_idx][mul_idx](column[mul_idx]);
      }
      result[result_idx] = sum;
    }
    return result;
  }

  aes_types::state_column mix_columns(aes_types::state_column column){
    return basic_mix_columns(column, aes_functions::mul_matrix);
  }
  State mix_columns(State state){
    State result;
    for (size_t i = 0; i < aes_constants::state_columns; i++){
      result.set_column(i, mix_columns(state.get_column(i)));
    }
    return result;
  }
  Message mix_columns(const Message& message){
    Message result = message;
    for (size_t i = 0; i < result.length(); i++){
      result.state(i) = mix_columns(result.state(i));
    }
    return result;
  }

  aes_types::state_column inv_mix_columns(aes_types::state_column column){
    return basic_mix_columns(column, aes_functions::inv_mul_matrix);
  }
  State inv_mix_columns(State state){
    State result;
    for (size_t i = 0; i < aes_constants::state_columns; i++){
      result.set_column(i, inv_mix_columns(state.get_column(i)));
    }
    return result;
  }
  Message inv_mix_columns(const Message& message){
    Message result = message;
    for (size_t i = 0; i < result.length(); i++){
      result.state(i) = inv_mix_columns(result.state(i));
    }
    return result;
  }
}