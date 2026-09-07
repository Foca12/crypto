#pragma once

#include "bytearray_helpers.hpp" 

namespace crypto
{
class Bytearray{
  bytearray_types::ilist bytes = {};

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
  
  // Creates an array of size bytes initialized to value
  Bytearray(size_t size = 0, uint8_t value = 0){
    this->bytes.insert(this->bytes.end(), size, value);
  }
  // Assigns a collection of bytes to the Bytearray
  Bytearray(const std::ranges::contiguous_range auto& bytes){
    this->bytes.assign(bytes.begin(), bytes.end());
  }

  // Extends the Bytearray by appending a single byte
  void push_back(uint8_t n){
    this->bytes.push_back(n);
  }
  // Merges the Bytearray with another collection
  void extend(const std::ranges::contiguous_range auto& bytes){
    this->bytes.insert(this->end(), bytes.begin(), bytes.end());
  }
  // Merges the Bytearray with another Bytearray
  void operator+=(const Bytearray& bytes){
    this->extend(bytes);
  }
  // Insert the x byte at pos position in the Bytearray
  void insert(int pos, uint8_t x){
    this->bytes.insert(this->begin() + this->handle_idx(pos), x);
  }

  // Removes the last element
  void pop_back(){
    this->bytes.pop_back();
  }
  // Removes the element at the specified index (supports negative indexing)
  void erase(int pos){
    pos = this->handle_idx(pos);
    this->bytes.erase(this->begin() + pos);
  }
  // Resizes the Bytearray by inserting or removing bytes until it reaches size length
  void resize(size_t size){
    this->bytes.resize(size);
  }

  // Sets all bytes to 0 and clears the content
  void clear(){
    this->fill(0);
    this->bytes.clear();
  }

  // Fills the entire container with the value x
  void fill(uint8_t x = 0){
    if(this->length() == 0) return;

    volatile uint8_t* start = this->bytes.data();
    for (size_t i = 0; i < this->length(); i++){
      start[i] = x;
    }
  }

  // Returns the Bytearray length
  size_t length() const {
    return this->bytes.size();
  }
  // Returns the Bytearray length
  size_t size() const {
    return this->bytes.size();
  }
  
  // Slices the Bytearray from start to stop, jumping by step
  Bytearray slice(int start, int stop, size_t step) const {
    size_t real_start = this->handle_idx(start);
    size_t real_stop = this->handle_idx(stop);

    if (real_start > this->length()){
      throw std::invalid_argument("Start index is bigger or equal than bytearray length");
    }
    if (real_stop > 0 && real_stop-1 > this->length()){
      throw std::invalid_argument("Stop index is bigger than bytearray length");
    }
    if (real_stop < real_start){
      throw std::invalid_argument("Stop index is lower than start index");
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
  // Slices the Bytearray from start to stop, jumping by 1
  Bytearray slice(int start, int stop) const {
    return this->slice(start, stop, 1);
  }
  // Slices the Bytearray from start to stop, jumping by 1
  Bytearray slice(int stop) const {
    return this->slice(0, stop, 1);
  }

  // Read-only access (supports negative indexing)
  const uint8_t& operator[](int idx) const {
    return this->bytes[this->handle_idx(idx)];
  }
  // Read-write access (supports negative indexing)
  uint8_t& operator[](int idx){
    return this->bytes[this->handle_idx(idx)];
  }
  
  // Constant iterator to the beginning
  bytearray_types::ilist_c_iterator begin() const {
    return this->bytes.begin();
  }
  // Iterator to the beginning
  bytearray_types::ilist_iterator begin() {
    return this->bytes.begin();
  }
  // Iterator to the end
  bytearray_types::ilist_iterator end() {
    return this->bytes.end();
  }
  // Constant iterator to the end
  bytearray_types::ilist_c_iterator end() const {
    return this->bytes.end();
  }
  
  // Constant pointer to first element
  uint8_t* data() {
    return this->bytes.data();
  }
  // Pointer to first element
  const uint8_t* data() const {
    return this->bytes.data();
  }

  // Increments the Bytearray considering the list as one number (prevents overflow by adding another digit)
  Bytearray& operator++(int){
    for (size_t i = 1; i <= this->length(); i++){
      this->operator[](-i)++;
      // if current element didn't go in overflow (wasn't 0xff)
      if (this->operator[](-i) > 0){
        return *this;
      }
    }
    // if all elements went in overflow (they were all 0xff)
    this->push_back(0);
    this->bytes[0] = 1;
    return *this;
  }
  // Increments the Bytearray considering the list as one number (prevents overflow by adding another digit)
  Bytearray& operator++(){
    return this->operator++(0);
  }
  // Decrements the Bytearray considering the list as one number (prevents overflow by not decrementing Bytearray)
  Bytearray& operator--(int){
    Bytearray sub = *this;
    for (size_t i = 1; i <= sub.length(); i++){
      sub[-i]--;

      // if last element was greather than 0 (uses static cast for calculate uint8 overflow)
      // if bytarray elements are all greather than 0 assignes the subtracted bytearray (prevents underflow)
      if (static_cast<uint8_t>(sub[-i] + 1) > 0){
        *this = sub;
        break;
      }
    }
    return *this;
  }
  // Decrements the Bytearray considering the list as one number (prevents overflow by not decrementing Bytearray)
  Bytearray& operator--(){
    return this->operator--(0);
  }

  // Returns true if both bytearray.bytes are the same, otherwise returnes false
  Bytearray& operator=(const Bytearray& x){
    this->bytes = x.bytes;
    return *this;
  }

  // Circular right shift of elements by rounds
  Bytearray shift_right(size_t rounds) const {
    Bytearray copy = *this;
    rounds = rounds % copy.length();

    if (rounds == 0 || copy.length() < 2){
      return copy;
    }
    
    // right element becomes left one
    for (int i = 0; i < copy.length(); i++){
      copy[i] = this->operator[](i-rounds);
    }
    return copy;
  }
  // Circular right shift of elements by rounds
  Bytearray shift_left(size_t rounds) const {
    Bytearray copy = *this;
    rounds = rounds % copy.length();

    if (rounds == 0 || copy.length() < 2){
      return copy;
    }
    
    // left element becomes right one
    for (int i = 0; i < copy.length(); i++){
      copy.operator[](i-rounds) = this->bytes[i];
    }
    return copy;
  }
  
  // Returns true if both bytearray.bytes are the same, otherwise returnes false
  bool operator==(const Bytearray& arr) const = default;

  // Element-wise bitwise OR
  Bytearray operator|(const Bytearray& arr) const {
    Bytearray result = *this;

    if (this->length() != arr.length()){
      throw std::invalid_argument("Mismatch between array lengths");
    }

    for (size_t i = 0; i < this->length(); i++){
      result[i] = result[i] | arr[i];
    }
    return result;
  }
  // Element-wise bitwise AND
  Bytearray operator&(const Bytearray& arr) const {
    Bytearray result = *this;

    if (this->length() != arr.length()){
      throw std::invalid_argument("Mismatch between array lengths");
    }

    for (size_t i = 0; i < this->length(); i++){
      result[i] = result[i] & arr[i];
    }
    return result;
  }
  // Element-wise bitwise XOR
  Bytearray operator^(const Bytearray& arr) const {
    Bytearray result = *this;

    if (this->length() != arr.length()){
      throw std::invalid_argument("Mismatch between array lengths");
    }

    for (size_t i = 0; i < this->length(); i++){
      result[i] = result[i] ^ arr[i];
    }
    return result;
  }
  // Element-wise bitwise NOT
  Bytearray operator~() const {
    Bytearray result = *this;
    for (uint8_t& i : result){
      i = ~i;
    }
    
    return result;
  }
  // Bitwise left shift by rounds
  Bytearray operator<<(size_t rounds) const {
    Bytearray result = *this;

    rounds %= result.length();

    for (uint8_t& i : result){
      i <<= rounds;
    }
    return result;
  }
  // Bitwise right shift by rounds
  Bytearray operator>>(size_t rounds) const {
    Bytearray result = *this;

    rounds %= result.length();

    for (uint8_t& i : result){
      i >>= rounds;
    }
    return result;
  }
  
  // Element-wise bitwise OR assignment
  Bytearray& operator|=(const Bytearray& arr) {
    return this->operator=(this->operator|(arr));
  }
  // Element-wise bitwise AND assignment
  Bytearray& operator&=(const Bytearray& arr) {
    return this->operator=(this->operator&(arr));
  }
  // Element-wise bitwise XOR assignment
  Bytearray& operator^=(const Bytearray& arr) {
    return this->operator=(this->operator^(arr));
  }
  // Bitwise left shift assignment
  Bytearray& operator<<=(size_t rounds) {
    return this->operator=(this->operator<<(rounds));
  }
  // Bitwise right shift assignment
  Bytearray& operator>>=(size_t rounds) {
    return this->operator=(this->operator>>(rounds));
  }

  // Returns an ASCII string if all bytes are valid, otherwise returns hex values formatted with \x
  operator std::string() const {
    return bytearray_functions::convert_to_string(this->bytes);
  }
  // Converts and returns the Bytearray as a crypto_types::ilist
  operator bytearray_types::ilist() const {
    return this->bytes;
  }

  // Converts all bytes to a hex-formatted string
  std::string hex() const {
    return bytearray_functions::basic_hex(this->bytes);
  }
  // Converts all bytes to a oct-formatted string
  std::string oct() const {
    return bytearray_functions::basic_oct(this->bytes);
  }

  // Creates a Bytearray from a string; foreach character in str, appends the byte to the result
  static Bytearray from_string (const std::string& str){
    return Bytearray(bytearray_functions::basic_from_string(str));
  }
  // Creates a Bytearray from a hex string; each byte must be exactly 2 
  static Bytearray from_hex (const std::string& str){
    return Bytearray(bytearray_functions::basic_from_hex(str));
  }
  // Creates a Bytearray from a oct string; each byte must be exactly 3
  static Bytearray from_oct (const std::string& str){
    return Bytearray(bytearray_functions::basic_from_oct(str));
  }
}; 
}