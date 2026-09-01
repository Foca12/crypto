#pragma once

#include "helpers.hpp" 

class Bytearray{
  crypto_types::ilist bytes = {};

  // helper function which calculates negative index
  size_t handle_idx(int idx) const {
    if (idx < 0){
      idx = this->length() + idx;
    }
    return idx;
  }

  public:
  ~Bytearray() {
    this->clear();
  }
  
  Bytearray(uint8_t x=0){
    this->bytes.insert(this->bytes.end(), x, 0);
  }
  Bytearray(const std::ranges::contiguous_range auto& bytes){
    this->bytes.assign(bytes.begin(), bytes.end());
  }

  void push_back(uint8_t n){
    this->bytes.push_back(n);
  }
  
  void extend(const std::ranges::contiguous_range auto& bytes){
    this->bytes.insert(this->end(), bytes.begin(), bytes.end());
  }

  void clear(){
    this->fill(0);
  }

  void fill(uint8_t x = 0){
    if(this->length() == 0) return;

    volatile uint8_t* start = this->bytes.data();
    for (size_t i = 0; i < this->length(); i++){
      start[i] = x;
    }
  }

  size_t length() const {
    return this->bytes.size();
  }
  size_t size() const {
    return this->bytes.size();
  }
  
  Bytearray slice(int start, int stop, size_t step) const {
    size_t real_start = this->handle_idx(start);
    size_t real_stop = this->handle_idx(stop);

    if (real_start > this->length()){
      throw std::invalid_argument("Start index is bigger or equal than bytearray length");
    }
    if (real_stop-1 > this->length()){
      throw std::invalid_argument("Stop index is bigger than bytearray length");
    }
    if (stop < start){
      throw std::invalid_argument("Stop index is lower or equal than start index");
    }
    if (step < 1){
      throw std::invalid_argument("Invalid step value");
    }

    Bytearray result;
    for (size_t i = start; i < stop; i += step){
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

  const uint8_t& operator[](int idx) const {
    return this->bytes[this->handle_idx(idx)];
  }
  uint8_t& operator[](int idx){
    return this->bytes[this->handle_idx(idx)];
  }
  
  crypto_types::ilist_c_iterator begin() const {
    return this->bytes.begin();
  }
  crypto_types::ilist_iterator begin() {
    return this->bytes.begin();
  }
  crypto_types::ilist_iterator end() {
    return this->begin()+this->length();
  }
  crypto_types::ilist_c_iterator end() const {
    return this->begin()+this->length();
  }
  
  Bytearray& operator=(const Bytearray& x){
    this->bytes = x.bytes;
    return *this;
  }

  // shift
  Bytearray shift_right(size_t rounds) const {
    Bytearray copy = *this;
    rounds = rounds % copy.length();

    if (rounds == 0 || copy.length() < 2){
      return copy;
    }
    
    // right element becomes left one
    for (size_t i = 0; i < copy.length(); i++){
      copy[i] = this->operator[](i-rounds);
    }
    return copy;
  }
  Bytearray shift_left(size_t rounds) const {
    Bytearray copy = *this;
    rounds = rounds % copy.length();

    if (rounds == 0 || copy.length() < 2){
      return copy;
    }
    
    // left element becomes right one
    for (size_t i = 0; i < copy.length(); i++){
      copy.operator[](i-rounds) = this->bytes[i];
    }
    return copy;
  }
  
  // logic operator
  Bytearray operator|(const Bytearray& arr) const {
    Bytearray result = *this;

    if (this->length() != arr.length()){
      throw std::invalid_argument("Mismatch between array lengths");
    }

    for (size_t i = 0; i < this->length(); i++){
      result.push_back(result[i] | arr[i]);
    }
    return result;
  }
  Bytearray operator&(const Bytearray& arr) const {
    Bytearray result = *this;

    if (this->length() != arr.length()){
      throw std::invalid_argument("Mismatch between array lengths");
    }

    for (size_t i = 0; i < this->length(); i++){
      result.push_back(result[i] & arr[i]);
    }
    return result;
  }
  Bytearray operator^(const Bytearray& arr) const {
    Bytearray result = *this;

    if (this->length() != arr.length()){
      throw std::invalid_argument("Mismatch between array lengths");
    }

    for (size_t i = 0; i < this->length(); i++){
      result.push_back(result[i] ^ arr[i]);
    }
    return result;
  }
  Bytearray operator~(){
    Bytearray result = *this;
    for (uint8_t& i : result){
      i = ~i;
    }
    
    return result;
  }
  Bytearray operator<<(size_t rounds) const {
    Bytearray result = *this;

    rounds %= result.length();

    for (uint8_t& i : result){
      i <<= rounds;
    }
    return result;
  }
  Bytearray operator>>(size_t rounds) const {
    Bytearray result = *this;

    rounds %= result.length();

    for (uint8_t& i : result){
      i >>= rounds;
    }
    return result;
  }
  
  
  Bytearray& operator|=(const Bytearray& arr) {
    return this->operator=(this->operator|(arr));
  }
  Bytearray& operator&=(const Bytearray& arr) {
    return this->operator=(this->operator&(arr));
  }
  Bytearray& operator^=(const Bytearray& arr) {
    return this->operator=(this->operator^(arr));
  }
  Bytearray& operator<<=(size_t rounds) {
    return this->operator=(this->operator<<(rounds));
  }
  Bytearray& operator>>=(size_t rounds) {
    return this->operator=(this->operator>>(rounds));
  }

  // conversioni di tipo
  operator std::string() const {
    return crypto_functions::convert_to_string(this->bytes);
  }
  operator crypto_types::ilist() const {
    return this->bytes;
  }

  // conversioni di formato
  std::string hex() const {
    return crypto_functions::basic_hex(this->bytes);
  }
  std::string oct() const {
    return crypto_functions::basic_oct(this->bytes);
  }

  // costruttori alternativi
  static Bytearray from_hex (const std::string& str){
    return Bytearray(crypto_functions::basic_from_hex(str));
  }
  static Bytearray from_oct (const std::string& str){
    return Bytearray(crypto_functions::basic_from_oct(str));
  }
}; 