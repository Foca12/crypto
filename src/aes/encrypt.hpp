#pragma once

#include "crypt/add_round_key.hpp"
#include "crypt/mix_columns.hpp"
#include "crypt/shift_rows.hpp"
#include "crypt/sub_bytes.hpp"
#include "message.hpp"
#include "key.hpp"

State encrypt_aes(State state, const Key& key){
  if (! key.is_expanded()){
    throw std::runtime_error("Trying to crypt a message with an unexpanded key, expand it by call key.expand()");
  }

  size_t rounds = key.get_specs().total_rounds;
  for (size_t round = 0; round <= rounds; round++){
    if (round > 0){
      state = crypt_operations::sub_bytes(state);
      state = crypt_operations::shift_rows(state);
      if (round < rounds){
        state = crypt_operations::mix_columns(state);
      }
    }
    state = crypt_operations::add_round_key(state, key, round);
  }
  return state;
}

Message encrypt_aes(Message message, const Key& key){
  // verifies padding integrity
  const State& last_state = message.state(-1);
  for (size_t i = 1; i <= last_state[-1]; i++){
    if (last_state[-i] != last_state[-1]){
      throw std::runtime_error("Message last state doesn't match PKCS#7 padding");
    }
  }

  for (size_t i = 0; i < message.length(); i++){
    message.state(i) = encrypt_aes(message.state(i), key);
  }

  return message;
}

Message encrypt_aes(Message message, const Key& key, const State& iv){
  // verifies padding integrity
  const State& last_state = message.state(-1);
  for (size_t i = 1; i <= last_state[-1]; i++){
    if (last_state[-i] != last_state[-1]){
      throw std::runtime_error("Message last state doesn't match PKCS#7 padding");
    }
  }

  for (size_t state_idx = 0; state_idx < message.length(); state_idx++){
    State& result = message.state(state_idx);
    result ^= state_idx == 0? iv : message.state(state_idx-1);
    result = encrypt_aes(result, key);

    message.state(state_idx) = result;
    }

  return message;
}


State decrypt_aes(State state, const Key& key){
  if (! key.is_expanded()){
    throw std::runtime_error("Trying to decrypt an encrypted message with an unexpanded key, expand it by call key.expand()");
  }

  size_t rounds = key.get_specs().total_rounds;
  size_t round = rounds+1;
  while (round --> 0){
    if (round < rounds){
        state = crypt_operations::inv_shift_rows(state);
        state = crypt_operations::inv_sub_bytes(state);
    }
    state = crypt_operations::add_round_key(state, key, round);
    if (round < rounds && round > 0){
      state = crypt_operations::inv_mix_columns(state);
    }
  }
  return state;
}

aes_types::ilist decrypt_aes(Message encrypted, const Key& key){
  for (size_t i = 0; i < encrypted.length(); i++){
    encrypted.state(i) = decrypt_aes(encrypted.state(i), key);
  }

  // verifies padding integrity
  const State& last_state = encrypted.state(-1);
  for (size_t i = 1; i <= last_state[-1]; i++){
    if (last_state[-i] != last_state[-1]){
      throw std::runtime_error("Message last state doesn't match PKCS#7 padding");
    }
  }

  // removes padding bytes
  aes_types::ilist result;
  result.assign(encrypted.begin(), encrypted.end()-encrypted[-1]);

  return result;
}

aes_types::ilist decrypt_aes(Message encrypted, const Key& key, const State& iv){
  Message decrypted = encrypted;
  for (size_t state_idx = 0; state_idx < encrypted.length(); state_idx++){
    State& result = decrypted.state(state_idx);
    result = decrypt_aes(result, key);
    result ^= state_idx == 0? iv : encrypted.state(state_idx-1);

    decrypted.state(state_idx) = result;
    }

  // verifies padding integrity
  const State& last_state = decrypted.state(-1);
  for (size_t i = 1; i <= last_state[-1]; i++){
    if (last_state[-i] != last_state[-1]){
      throw std::runtime_error("Message last state doesn't match PKCS#7 padding");
    }
  }

  // removes padding bytes
  aes_types::ilist result;
  result.assign(decrypted.begin(), decrypted.end()-decrypted[-1]);

  return result;
}