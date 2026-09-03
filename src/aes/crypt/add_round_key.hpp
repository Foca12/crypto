#pragma once

#include "../aes_helpers.hpp"
#include "../state.hpp"
#include "../message.hpp"
#include "../key.hpp"

namespace crypt_operations
{
  State add_round_key(State state, const Key& key, size_t round){
    auto specs = key.get_specs();
    
    if (round > specs.total_rounds){
      throw std::out_of_range("Round index is bigger than key rounds");
    }

    size_t first_key_word_idx = round*aes_constants::state_columns;
    aes_types::state_matrix_column columns = state.get_columns();

    // foreach word in state
    for (size_t word_idx = 0; word_idx < aes_constants::state_columns; word_idx++){

      Bytearray current_state_word = columns[word_idx];
      Bytearray current_key_word = key.get_words()[first_key_word_idx+word_idx];

      current_state_word ^= current_key_word;

      state.set_column(word_idx, current_state_word);
    }

    return state;
  }
  
  Message add_round_key(Message message, const Key& key, size_t round){
    for (State& state : message.state_iterator()){
      state = crypt_operations::add_round_key(state, key, round);
    }
    return message;
  }
}
