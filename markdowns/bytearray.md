# Description

This is a generic container for bytes and serves as the default collection of the library. It provides different utility methods and features Python-like negative indexing to simplify data access.

# Usage

## 🏗️ Constructors & Factory Methods

```cpp
Bytearray(size_t size = 0) // Creates an array of 'size' bytes initialized to 0
Bytearray(const std::ranges::contiguous_range auto& bytes) // Assigns a collection of bytes to the Bytearray

static Bytearray from_hex(const std::string& str) // Creates a Bytearray from a hex string; each byte must be exactly 2 characters long
static Bytearray from_oct(const std::string& str) // Creates a Bytearray from an octal string; each byte must be exactly 3 characters long
```

## ➕ Modifying Operations (Non-Const)

```cpp
void push_back(uint8_t n) // Extends the Bytearray by appending a single byte
void extend(const std::ranges::contiguous_range auto& bytes) // Merges the Bytearray with another collection

void pop_back() // Removes the last element
void erase(int pos) // Removes the element at the specified index (supports negative indexing)

void clear() // Sets all bytes to 0 and clears the content
void fill(uint8_t x = 0) // Fills the entire container with the value 'x'

Bytearray& operator++(int) // Increments the Bytearray considering the list as one number (prevents overflow by adding another digit)
Bytearray& operator++()    // Same as before
Bytearray& operator--(int) // Decrements the Bytearray considering the list as one number (prevents overflow by not decrementing Bytearray)
Bytearray& operator--()    // Same as before

Bytearray& operator=(const Bytearray& x) // Copy assignment operator
```

## 🔍 Inspection & Access (Const)

```cpp
size_t length() const // Returns the Bytearray length
size_t size() const   // Same as length()

Bytearray slice(int start, int stop, size_t step) const // Slices the Bytearray from 'start' to 'stop', jumping by 'step'
Bytearray slice(int start, int stop) const              // Slices the Bytearray from 'start' to 'stop' with step = 1
Bytearray slice(int stop) const                         // Slices the Bytearray from index 0 to 'stop' with step = 1

const uint8_t& operator[](int idx) const // Read-only access (supports negative indexing)
uint8_t& operator[](int idx)             // Read-write access (supports negative indexing)
```

## 🔄 Iterators

```cpp
crypto_types::ilist_c_iterator begin() const // Constant iterator to the beginning
crypto_types::ilist_iterator begin()         // Iterator to the beginning
crypto_types::ilist_c_iterator end() const   // Constant iterator to the end
crypto_types::ilist_iterator end()           // Iterator to the end
```

## 🔀 Bitwise & Shift Operations

```cpp
Bytearray shift_right(size_t rounds) const // Circular right shift of elements by 'rounds'
Bytearray shift_left(size_t rounds) const  // Circular left shift of elements by 'rounds'

Bytearray operator|(const Bytearray& arr) const  // Element-wise bitwise OR
Bytearray operator&(const Bytearray& arr) const  // Element-wise bitwise AND
Bytearray operator^(const Bytearray& arr) const  // Element-wise bitwise XOR
Bytearray operator~() const                      // Element-wise bitwise NOT
Bytearray operator<<(size_t rounds) const        // Bitwise left shift by 'rounds'
Bytearray operator>>(size_t rounds) const        // Bitwise right shift by 'rounds'

Bytearray& operator|=(const Bytearray& arr)  // Element-wise bitwise OR assignment
Bytearray& operator&=(const Bytearray& arr)  // Element-wise bitwise AND assignment
Bytearray& operator^=(const Bytearray& arr)  // Element-wise bitwise XOR assignment
Bytearray& operator<<=(size_t rounds)        // Bitwise left shift assignment
Bytearray& operator>>=(size_t rounds)        // Bitwise right shift assignment
```

## 💱 Conversions & Type Casting

```cpp
operator std::string() const // Returns an ASCII string if all bytes are valid, otherwise returns hex values formatted with '\x'
operator crypto_types::ilist() const // Converts and returns the Bytearray as a crypto_types::ilist

std::string hex() const // Converts all bytes to a hex-formatted string
std::string oct() const // Converts all bytes to an octal-formatted string
```
