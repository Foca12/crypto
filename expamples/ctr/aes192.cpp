#include <iostream>
#include "../../include/aes.hpp"
#include "../../include/bytearray.hpp"

using namespace std;

typedef struct {
  string key;
  string plain;
  string cipher;
} test;

constexpr size_t n_tests = 7;

const string test_iv = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

const test tests[n_tests] = {
  // --- NIST Vectors ---
  {"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
  "6bc1bee22e409f96e93d7e117393172a",
  "1abc932417521ca24f2b0459fe7e6e0b",},

  {"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
  "ae2d8a571e03ac9c9eb76fac45af8e51",
  "090339ec0aa6faefd5ccc2c6f4ce8e94",},

  {"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
  "30c81c46a35ce411e5fbc1191a0a52ef",
  "1e36b26bd1ebc670d1bd1d665620abf7",},

  {"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
  "f69f2445df4f9b17ad2b417be66c3710",
  "4f78a7f6d29809585a97daec58c6b050",},
    
  // --- Recurring Pattern --- 
  {"000102030405060708090a0b0c0d0e0f",
   "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
   "6b10801b69c335150c1b73a933236fc2e92503c321815f2920148fc58c92d67c"},

  // --- All-Zeros Test Vector ---
  {"000000000000000000000000000000000000000000000000",
   "000000000000000000000000000000000000000000000000",
   "5707b61b75d1439d92b16ff8eb8f5e6d8ba38e40f875c749"},

  // --- Asimmetric Vector ---
  {"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
   "6bc1bee22e409f96e93d7e117393172a11223344",
   "48264ddf816647e965496ac3fd86dacf89a24e4b"}
};


int main(){
  cout << "START OF THE TEST OF THE LIBRARY (AES-192 CTR)" << endl;
  
  int passed = 0;
  int failed = 0;

  Bytearray iv = Bytearray::from_hex(test_iv);
  for (int i = 0; i < n_tests; i++){
    Bytearray key = Bytearray::from_hex(tests[i].key);

    Bytearray plain = Bytearray::from_hex(tests[i].plain);
    string cipher = tests[i].cipher;

    Bytearray my_cipher = encrypt_aes(plain, key, iv, CTR);
    
    aes_types::ilist my_decipher = decrypt_aes(my_cipher, key, iv, CTR);

    bool round_error = false;

    if (my_cipher.hex() != cipher){
      cout << "Encrypt error in test number [" << i << "] -> Expected: " << cipher << " | Calculated: " << my_cipher.hex() << endl;
      round_error = true;
    }
    
    if (aes_functions::basic_hex(my_decipher) != tests[i].plain){
      cout << "Decrypt error in test number [" << i << "] -> Expected: " << tests[i].plain << " | Calculated: " << aes_functions::basic_hex(my_decipher) << endl;
      round_error = true;
    }

    iv++;

    if (!round_error) {
      passed++;
    } else {
      failed++;
    }
  }
  
  cout << "\n=== TEST RESULT ===" << endl;
  cout << "Passed: " << passed << "/" << n_tests << endl;
  cout << "Failed: " << failed << "/" << n_tests << endl;
  cout << "END OF THE TEST" << endl;
  
  return 0;
}