#pragma once

#include "aes_helpers.hpp"

class State{
  aes_types::state_arr bytes = {};

  // helper functions that calculate negative indexes and check for indixes exceeding the maximum length
  static size_t handle_row_idx(int idx){
    int result = idx < 0? aes_constants::state_rows + idx : idx;

    if (result >= aes_constants::state_rows){
      throw std::out_of_range("Row idx exceeded state rows");
    }

    return static_cast<size_t>(result);
  }
  static size_t handle_column_idx(int idx){
    size_t result = idx < 0? aes_constants::state_columns + idx : idx;

    if (result >= aes_constants::state_columns){
      throw std::out_of_range("Column idx exceeded state columns");
    }

    return static_cast<size_t>(result);
  }
  static size_t handle_idx(int idx){
    int result = idx < 0? aes_constants::state_chars + idx : idx;

    if (result >= aes_constants::state_chars){
      throw std::out_of_range("Column idx exceeded state chars");
    }
    
    return static_cast<size_t>(result);
  }

  public:
  ~State() {
    this->clear();
  }
  
  State(uint8_t x = aes_constants::state_chars){
    this->fill(x);
  }
  State(const Bytearray& bytes){
    if (bytes.size() > aes_constants::state_chars){
      throw std::invalid_argument("Input vector is bigger than state dimension");
    }
    
    // creates padding
    this->fill(aes_constants::state_chars - bytes.size());
    std::copy(bytes.begin(), bytes.end(), this->begin());
  };
  

  void fill(uint8_t x){
    volatile uint8_t* ptr = this->bytes.data();
    for (size_t i = 0; i < aes_constants::state_chars; i++){
      ptr[i] = x;
    }
  }
  void clear(){
    this->fill(aes_constants::state_chars);
  }
  
  aes_types::state_matrix_row get_rows() const {
    aes_types::state_matrix_row result_rows = {};
    // foreach row
    for (size_t idx = 0; idx < aes_constants::state_rows; idx++){
      result_rows[idx] = this->get_row(idx);
    }
    return result_rows;
  }
  Bytearray get_row(int row_idx) const {
    size_t idx = State::handle_row_idx(row_idx);

    Bytearray row;
    // foreach row
    for (size_t i = 0; i < aes_constants::state_columns; i ++){
      size_t row_start = i*aes_constants::state_rows;
      row.push_back(this->bytes[row_start+idx]);
    }
    return row;
  }
  void set_row(int row_idx, const Bytearray& value){
    size_t idx = State::handle_row_idx(row_idx);

    for (size_t i = 0; i < aes_constants::state_columns; i ++){
      size_t row_start = i*aes_constants::state_rows;
      this->bytes[row_start+idx] = value[i];
    }
  }

  aes_types::state_matrix_column get_columns() const {
    aes_types::state_matrix_column result_columns;
    // foreach column
    for (size_t idx = 0; idx < aes_constants::state_columns; idx++){
      result_columns[idx] = this->get_column(idx);
    }
    return result_columns;
  }
  Bytearray get_column(int column_idx) const {
    size_t idx = State::handle_column_idx(column_idx);

    Bytearray column;
    // start of the column
    size_t column_start = idx*aes_constants::state_rows;
    
    for (size_t i = 0; i < aes_constants::state_rows; i ++){
      column.push_back(bytes[column_start+i]);
    }
    return column;
  }
  void set_column(int idx, const Bytearray& value){
    size_t column_idx = State::handle_column_idx(idx);

    for (size_t i = column_idx*aes_constants::state_rows; i < column_idx*aes_constants::state_rows+aes_constants::state_rows; i ++){
      this->bytes[i] = value[i-(column_idx*aes_constants::state_rows)];
    }
  }
  
  typename aes_types::iarr_c_iterator<aes_constants::state_chars> begin() const {
    return this->bytes.begin();
  }
  typename aes_types::iarr_c_iterator<aes_constants::state_chars> end() const {
    return this->bytes.end();
  }
  typename aes_types::iarr_iterator<aes_constants::state_chars> begin() {
    return this->bytes.begin();
  }
  typename aes_types::iarr_iterator<aes_constants::state_chars> end() {
    return this->bytes.end();
  }

  uint8_t operator[](int idx) const {
    return this->bytes[State::handle_idx(idx)];
  }
  uint8_t& operator[](int idx){
    return this->bytes[State::handle_idx(idx)];
  }

  Bytearray slice(int start, int stop, size_t step) const {
    size_t real_start = State::handle_idx(start);
    size_t real_stop = State::handle_idx(stop);

    if (real_start > aes_constants::state_chars){
      throw std::invalid_argument("Start index is bigger or equal than bytearray length");
    }
    if (real_stop-1 > aes_constants::state_chars){
      throw std::invalid_argument("Stop index is bigger than bytearray length");
    }
    if (real_stop-1 <= real_start){
      throw std::invalid_argument("Stop index is lower or equal than start index");
    }
    if (step < 1){
      throw std::invalid_argument("Invalid step value");
    }
    
    Bytearray result;
    for (size_t i = real_start; i < real_stop; i += step){
      result.push_back(this->bytes[i]);
    }
    return result;
  }
  Bytearray slice(int start, int stop) const {
    return this->slice(start, stop, 1);
  }
  Bytearray slice(int stop) const {
    return this->slice(0, stop, 1);
  }

  State& operator=(const State& x){
    for (size_t i = 0; i < aes_constants::state_chars; i++){
      this->operator[](i) = x.bytes[i];
    }
    return *this;
  }

  State operator^(const State& key) const {
    State copy = key;
    for (size_t i = 0; i < aes_constants::state_chars; i++){
      copy[i] ^= this->operator[](i);
    }
    return copy;
  }
  State operator&(const State& key) const {
    State copy = key;
    for (size_t i = 0; i < aes_constants::state_chars; i++){
      copy[i] &= this->operator[](i);
    }
    return copy;
  }
  State operator|(const State& key) const {
    State copy = key;
    for (size_t i = 0; i < aes_constants::state_chars; i++){
      copy[i] |= this->operator[](i);
    }
    return copy;
  }
  State operator~() const {
    State result = *this;
    for (uint8_t& i : result){
      i = ~i;
    }
    return result;
  }
  
  State& operator^=(const State& key) {
    return this->operator=(this->operator^(key));
  }
  State& operator&=(const State& key) {
    return this->operator=(this->operator&(key));
  }
  State& operator|=(const State& key) {
    return this->operator=(this->operator|(key));
  }

  State operator>>(size_t rounds) const {
    State copy = *this;
    for (size_t i = 0; i < aes_constants::state_chars; i++){
      copy[i] >>= rounds;
    }
    return copy;
  } 
  State operator<<(size_t rounds) const {
    State copy = *this;
    for (size_t i = 0; i < aes_constants::state_chars; i++){
      copy[i] <<= rounds;
    }
    return copy;
  } 

  State& operator<<=(size_t rounds) {
    return this->operator=(this->operator<<(rounds));
  }
  State& operator>>=(size_t rounds) {
    return this->operator=(this->operator>>(rounds));
  }

  State shift_left(size_t rounds) const {
    rounds %= aes_constants::state_columns;
    if (rounds == 0){
      return *this;
    }

    State result = *this;

    for (size_t row_idx = 0; row_idx < aes_constants::state_rows; row_idx++){
      Bytearray row_result = result.get_row(row_idx);
      Bytearray row_copy = result.get_row(row_idx);
      
      // left character becomes right character
      for (size_t char_idx = 0; char_idx < aes_constants::state_columns; char_idx ++){
        row_result[char_idx] = row_copy[(char_idx+rounds) % aes_constants::state_columns];
      }

      result.set_row(row_idx, row_result);
    }
    return result;
  }
  State shift_right(size_t rounds) const {
    rounds %= aes_constants::state_columns;
    if (rounds == 0){
      return *this;
    }

    State result = *this;

    for (size_t row_idx = 0; row_idx < aes_constants::state_rows; row_idx++){
      Bytearray row_result = result.get_row(row_idx);
      Bytearray row_copy = result.get_row(row_idx);
      
      // right character becomes left character
      for (size_t char_idx = 0; char_idx < aes_constants::state_columns; char_idx ++){
        size_t copy_idx = char_idx-rounds;
        if (char_idx-rounds < 0) {
          copy_idx = aes_constants::state_columns+copy_idx;
        }
        
        row_result[char_idx] = row_copy[copy_idx];
      }

      result.set_row(row_idx, row_result);
    }
    return result;
  }

  operator Bytearray() {
    Bytearray result;
    std::copy(this->bytes.begin(), this->bytes.end(), result.begin());
    return result;
  }
  operator aes_types::state_arr() {
    return this->bytes;
  }
  operator std::string() {
    return aes_functions::convert_to_string(this->bytes);
  }

  std::string hex() const {
    return aes_functions::basic_hex(this->bytes);
  }
  std::string oct() const {
    return aes_functions::basic_oct(this->bytes);
  }

  static State from_hex(const std::string& str){
    return State(aes_functions::basic_from_hex(str));
  }
  static State from_oct(const std::string& str){
    return State(aes_functions::basic_from_hex(str));
  }
};
