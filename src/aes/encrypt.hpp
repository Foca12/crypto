#pragma once

#include "crypt/add_round_key.hpp"
#include "crypt/mix_columns.hpp"
#include "crypt/shift_rows.hpp"
#include "crypt/sub_bytes.hpp"
#include "../bytearray.hpp"
#include "message.hpp"
#include "key.hpp"

enum Mode {CBC, CTR};

namespace aes_functions {
  // verifies padding integrity
  void check_padding(Bytearray& bytes, bool remove_padding){
    uint8_t padding = bytes[-1];
    for (size_t i = 1; i <= padding; i++){
      // if remove_padding, at every iteration bytes.length decrements by itself
      // else length remains the as same as the start and it has to move trough the bytearray 

      if (bytes[remove_padding? -1 : -i] != padding){
        throw std::runtime_error("Message last state doesn't match PKCS#7 padding");
      }
      if (remove_padding) {
        bytes.pop_back();
      }
    }
  }
}

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
Bytearray encrypt_aes(const Bytearray& plain, const Key& key){
  Message message = Message::divide_bytearray(plain);

  for (State& state : message.state_iterator()){
    state = encrypt_aes(state, key);
  }

  return message;
}

// encrypts using CBC or CTR mode
Bytearray encrypt_aes(const Bytearray& plain, const Key& key, const Bytearray& iv, const Mode& mode){
  Bytearray cipher;

  switch (mode){
    case CBC: {
      Message message = Message::divide_bytearray(plain);

      // verifies iv length
      if (iv.length() != aes_constants::state_chars){
        throw std::invalid_argument("Iv length length be equal to the state length");
      }

      State real_iv (iv);

      // foreach state calculates encrypt and calculates xor with previous iv or encrypted state
      for (size_t state_idx = 0; state_idx < message.length(); state_idx++){
        State& result = message.state(state_idx);
        result ^= state_idx == 0? real_iv : message.state(state_idx-1);
        result = encrypt_aes(result, key);

        cipher.extend(Bytearray(result));
      }

      break;
    }

    case CTR: {
      Message message = Message::divide_bytearray(plain);

      // verifies iv length
      if (iv.length() != aes_constants::ctr_nonce_length){
        throw std::invalid_argument("Iv length length be "+std::to_string(aes_constants::ctr_nonce_length));
      }

      size_t padding = message[-1];
      Bytearray counter(aes_constants::ctr_counter_length);
      for (size_t state_idx = 0; state_idx < message.length(); state_idx++){
        // creates the keystream by coping start nonce/iv, appending counter and encrypting it
        Bytearray keystream = iv;
        keystream.extend(counter);
        keystream = encrypt_aes(keystream, key);

        // prevents the adding of the padding
        size_t end;
        // if it's the last iteration stop before start of the padding
        if (state_idx == message.length()-1){
          end = aes_constants::state_chars - padding;
        }
        else {
          end = aes_constants::state_chars;
        }

        // calculates xor between current state and ciphred keystream
        const State& current_state = message.state(state_idx);
        for (size_t char_idx = 0; char_idx < end; char_idx++){
          cipher.push_back(current_state[char_idx] ^ keystream[char_idx]);
        }

        // increments counter
        counter++;
      }

      break;
    }
  }
  
  return cipher;
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
  aes_functions::check_padding(result, true);

  return result;
}

// decrypts using CBC or CTR mode
Bytearray decrypt_aes(const Bytearray& cipher, const Key& key, const Bytearray& iv, const Mode& mode, bool remove_padding = true){
  Bytearray decipher;

  switch (mode){
    case CBC: {
      State real_iv (iv);
      Message encrypted = Message::divide_bytearray(cipher);
      encrypted.squeeze(); // removes extra state padding

      if (iv.length() != aes_constants::state_chars){
        throw std::invalid_argument("Iv length length be equal to the state length");
      }

      // foreach state in encrypted
      for (size_t state_idx = 0; state_idx < encrypted.length(); state_idx++){
        // decrypts single state and calculates xor with iv or previous encrypted state
        State result = encrypted.state(state_idx);
        result = decrypt_aes(result, key);
        result ^= state_idx == 0? real_iv : encrypted.state(state_idx-1);
      
        decipher.extend(Bytearray(result));
      }

      aes_functions::check_padding(decipher, true);

      break;
    }

    case CTR: {
      decipher = encrypt_aes(cipher, key, iv, CTR);

      aes_functions::check_padding(decipher, true);
    }
  }

  return decipher;
}