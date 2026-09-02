#pragma once

#include "crypt/add_round_key.hpp"
#include "crypt/mix_columns.hpp"
#include "crypt/shift_rows.hpp"
#include "crypt/sub_bytes.hpp"
#include "../bytearray.hpp"
#include "message.hpp"
#include "key.hpp"


// encrypts a single state
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

// encrypts using ECB mode
Bytearray encrypt_aes(const Bytearray& plain, const Key& key, bool squeeze_padding = false){
  Message message = Message::divide_bytearray(plain);

  // verifies padding integrity
  const State& last_state = message.state(-1);
  for (size_t i = 1; i <= last_state[-1]; i++){
    if (last_state[-i] != last_state[-1]){
      throw std::runtime_error("Message last state doesn't match PKCS#7 padding");
    }
  }

  for (State& state : message.state_iterator()){
    state = encrypt_aes(state, key);
  }

  if (squeeze_padding){
    message.squeeze();
  }

  return message;
}

// encrypts using CBC mode
Bytearray encrypt_aes(const Bytearray& plain, const Key& key, const Bytearray& iv, bool squeeze_padding = false){
  Message message = Message::divide_bytearray(plain);
  State real_iv (iv);
  
  // verifies padding integrity
  const State& last_state = message.state(-1);
  for (size_t i = 1; i <= last_state[-1]; i++){
    if (last_state[-i] != last_state[-1]){
      throw std::runtime_error("Message last state doesn't match PKCS#7 padding");
    }
  }

  if (iv.length() != aes_constants::state_chars){
    throw std::invalid_argument("Iv length length be equal to the state length");
  }

  // foreach state calculates encrypt and calculates xor with previous iv or encrypted state
  for (size_t state_idx = 0; state_idx < message.length(); state_idx++){
    State& result = message.state(state_idx);
    result ^= state_idx == 0? real_iv : message.state(state_idx-1);
    result = encrypt_aes(result, key);

    message.state(state_idx) = result;
    }

  if (squeeze_padding){
    message.squeeze();
  }

  return message;
}

// decrypts a single state
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

// decrypts using ECB mode
Bytearray decrypt_aes(const Bytearray& cipher, const Key& key, bool remove_padding = true){
  Message encrypted = Message::divide_bytearray(cipher);
  encrypted.squeeze(); // removes extra state padding

  for (State& state : encrypted.state_iterator()){
    state = decrypt_aes(state, key);
  }

  Bytearray result = encrypted;
  // verifies padding integrity and removes it
  const State& last_state = encrypted.state(-1);
  for (size_t i = 1; i <= last_state[-1]; i++){
    if (last_state[-i] != last_state[-1]){
      throw std::runtime_error("Message last state doesn't match PKCS#7 padding");
    }
    if (remove_padding){
      result.pop_back();
    }
  }

  return result;
}

// decrypts using CBC mode
Bytearray decrypt_aes(const Bytearray& cipher, const Key& key, const Bytearray& iv, bool remove_padding=true){
  State real_iv (iv);
  Message encrypted = Message::divide_bytearray(cipher);
  Message decrypted = encrypted;
  decrypted.squeeze(); // removes extra state padding

  if (iv.length() != aes_constants::state_chars){
    throw std::invalid_argument("Iv length length be equal to the state length");
  }

  // foreach state in decrypted
  for (size_t state_idx = 0; state_idx < decrypted.length(); state_idx++){
    // decrypts single state and calculates xor with iv or previous encrypted state
    State& result = decrypted.state(state_idx);
    result = decrypt_aes(result, key);
    result ^= state_idx == 0? real_iv : encrypted.state(state_idx-1);

    decrypted.state(state_idx) = result;
    }

  Bytearray result = decrypted;
  // verifies padding integrity and removes it
  const State& last_state = decrypted.state(-1);
  for (size_t i = 1; i <= last_state[-1]; i++){
    if (last_state[-i] != last_state[-1]){
      throw std::runtime_error("Message last state doesn't match PKCS#7 padding");
    }
    if (remove_padding){
      result.pop_back();
    }
  }

  return result;
}