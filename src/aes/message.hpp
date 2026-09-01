#pragma once

#include "aes_helpers.hpp"
#include "../bytearray.hpp"
#include "state.hpp"

class Message {
  aes_types::message_vct states;

  // helper functions that calculate negative indexes and check for indixes exceeding the maximum length
  size_t handle_state_idx(const int idx) const {
    size_t result = idx < 0? this->states.size() + idx : idx;
    if (result >= this->states.size()){
      throw std::out_of_range("Message state idx is exceeded maximum length");
    }
    return result;
  }
  size_t handle_idx(const int idx) const {
    size_t result = idx < 0? this->states.size() * aes_constants::state_chars + idx : idx;
    if (result >= this->states.size() * aes_constants::state_chars){
      throw std::out_of_range("Message state idx is exceeded maximum length");
    }
    return result;
  }

  struct support_state_c_iterator {
    const aes_types::message_vct& support_states;

    aes_types::message_c_iterator begin() const {
      return this->support_states.begin();
    }
    aes_types::message_c_iterator end() const {
      return this->support_states.end();
    }
  };
  struct support_state_iterator {
    aes_types::message_vct& support_states;

    aes_types::message_iterator begin(){
      return this->support_states.begin();
    }
    aes_types::message_iterator end(){
      return this->support_states.end();
    }
  };

  public:
  ~Message() {
    // clear memory 
    this->clear();
  }
  
  Message(size_t len = 0){
    this->states.resize(len, State ());
  }
  Message(const aes_types::message_vct& list){
    this->states = list;
  }

  static Message divide_string(const std::string& bytes){
    Bytearray arr;
    for (auto i : bytes){
      arr.push_back(static_cast<uint8_t> (i));
    }
    return Message::divide_bytearray(arr);
  }
  static Message divide_bytearray(Bytearray bytes){
    // total states
    size_t states = bytes.size() / aes_constants::state_chars + 1;
    Message message (states);

    // foreach full state
    for (size_t state_idx = 0; state_idx < states-1; state_idx++){
      // slices bytes into State
      size_t start_offset = state_idx*aes_constants::state_chars;
      size_t end_offset = (state_idx+1)*aes_constants::state_chars;
      State current (bytes.slice(start_offset, end_offset));

      message.state(state_idx) = current;
    }
    
    // last state
    State current (aes_constants::state_chars - bytes.size() + (states-1)*aes_constants::state_chars);
    size_t start_offset = (states-1)*aes_constants::state_chars;
    std::copy(bytes.begin()+start_offset, bytes.end(), current.begin());

    message.state(states-1) = current;

    return message;
  }

  void squeeze() {
    if (this->state(-1)[-1] == aes_constants::state_chars){
      this->states.pop_back();
    }
  }

  void clear() {
    for (State& current_state : this->states){
      current_state.clear();
    }
  }

  int length() const {
    return this->states.size();
  }
  int size() const {
    return this->length();
  }
  
  uint8_t& operator[](int id) {
    size_t idx = this->handle_idx(id);
    size_t state_idx = idx / aes_constants::state_chars;
    size_t element_idx = idx % aes_constants::state_chars;

    return this->states[state_idx][element_idx];
  }
  uint8_t operator[](int id) const {
    size_t idx = this->handle_idx(id);
    size_t state_idx = idx / aes_constants::state_chars;
    size_t element_idx = idx % aes_constants::state_chars;

    return this->states[state_idx][element_idx];
  }
  State& state(int idx){
    size_t state_idx = this->handle_state_idx(idx);
    return this->states[state_idx];
  }
  const State& state(int idx) const {
    size_t state_idx = this->handle_state_idx(idx);
    return this->states[state_idx];
  }

  typename aes_types::iarr_c_iterator<aes_constants::state_chars> begin() const {
    return this->state(0).begin();
  }
  typename aes_types::iarr_c_iterator<aes_constants::state_chars> end() const {
    return this->state(-1).end();
  }
  typename aes_types::iarr_iterator<aes_constants::state_chars> begin() {
    return this->state(0).begin();
  }
  typename aes_types::iarr_iterator<aes_constants::state_chars> end() {
    return this->state(-1).end();
  }
  
  support_state_c_iterator state_iterator() const {
    return support_state_c_iterator{this->states};
  }
  support_state_iterator state_iterator() {
    return support_state_iterator{this->states};
  }

  Message& operator=(const Message& message){
    this->states = message.states;
    return *this;
  }

  Message operator^(const State& state) const {
    Message result = *this;
    for (size_t i = 0; i < result.length(); i++){
      result.state(i) = result.state(i) ^ state;
    }
    return result;
  }
  Message operator&(const State& state) const {
    Message result = *this;
    for (size_t i = 0; i < result.length(); i++){
      result.state(i) = result.state(i) & state;
    }
    return result;
  }
  Message operator|(const State& state) const {
    Message result = *this;
    for (size_t i = 0; i < result.length(); i++){
      result.state(i) = result.state(i) | state;
    }
    return result;
  }

  Message& operator^=(const State& state) {
    return this->operator=(this->operator^(state));
  }
  Message& operator&=(const State& state) {
    return this->operator=(this->operator&(state));
  }
  Message& operator|=(const State& state) {
    return this->operator=(this->operator|(state));
  }

  Message operator>> (const size_t rounds) const {
    Message result = *this;
    for (size_t i = 0; i < result.length(); i++){
      result.state(i) = result.state(i) >> rounds;
    }
    return result;
  }
  Message operator<< (const size_t rounds) const {
    Message result = *this;
    for (size_t i = 0; i < result.length(); i++){
      result.state(i) = result.state(i) << rounds;
    }
    return result;
  }

  Message& operator>>=(const size_t rounds) {
    return this->operator=(this->operator>>(rounds));
  }
  Message& operator<<=(const size_t rounds) {
    return this->operator=(this->operator<<(rounds));
  }

  Message shift_left(size_t rounds) const {
    Message result = *this;
    for (size_t i = 0; i < result.length(); i++){
      result.state(i) = result.state(i).shift_left(rounds);
    }
    return result;
  }
  Message shift_right(size_t rounds) const {
    Message result = *this;
    for (size_t i = 0; i < result.length(); i++){
      result.state(i) = result.state(i).shift_right(rounds);
    }
    return result;
  }

  // type cast
  operator std::string() const {
    std::string str = "";
    for (auto i : this->state_iterator()){
      str += (std::string)i;
    }
    return str;
  }
  operator Bytearray() const {
    Bytearray list = {};
    for (State i : this->states){
      list.extend(static_cast<Bytearray>(i));
    }
    return list;
  }

  // format conversion
  std::string hex() const {
    std::string str = "";
    
    for (State i : this->states) {
      str += i.hex();
    }

    return str;
  }
  std::string oct() const {
    std::string str = "";
    
    for (State i : this->states) {
      str += i.oct();
    }

    return str;
  }

  static Message from_hex(const std::string& str){
    aes_types::ilist array = aes_functions::basic_from_hex(str);
    return Message::divide_bytearray(array);
  }
  static Message from_oct(const std::string& str){
    aes_types::ilist array = aes_functions::basic_from_oct(str);
    return Message::divide_bytearray(array);
  }
};