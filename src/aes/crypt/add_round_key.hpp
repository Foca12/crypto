#pragma once

#include "../helpers.hpp"
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

    // foreach word in state
    for (size_t word_idx = 0; word_idx < aes_constants::state_columns; word_idx++){
      size_t first_key_word_idx = round*aes_constants::state_columns;

      aes_types::state_column current_state_word = state.get_column(word_idx);
      aes_types::state_column current_key_word = key.get_words()[first_key_word_idx+word_idx];

      // foreach char in word
      for (size_t char_idx = 0; char_idx < aes_constants::state_columns; char_idx++){
        current_state_word[char_idx] ^= current_key_word[char_idx];
      }

      state.set_column(word_idx, current_state_word);
    }

    return state;
  }
  
  Message add_round_key(Message message, const Key& key, size_t round){
    for (size_t i = 0; i < message.length(); i++){
      message.state(i) = crypt_operations::add_round_key(message.state(i), key, round);
    }
    return message;
  }
}
