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

const test tests[n_tests] = { 
  // --- NIST Vectors ---
  {"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
   "6bc1bee22e409f96e93d7e117393172a",
   "bd334f1d6e45f25ff712a214571fa5ccdaa0af074bd8083c8a32d4fc563c55cc"},

  {"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
   "ae2d8a571e03ac9c9eb76fac45af8e51",
   "974104846d0ad3ad7734ecb3ecee4eefdaa0af074bd8083c8a32d4fc563c55cc"},

  {"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
   "30c81c46a35ce411e5fbc1191a0a52ef",
   "ef7afd2270e2e60adce0ba2face6444edaa0af074bd8083c8a32d4fc563c55cc"},

  {"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
   "f69f2445df4f9b17ad2b417be66c3710",
   "9a4b41ba738d6c72fb16691603c18e0edaa0af074bd8083c8a32d4fc563c55cc"},

  // --- Recurring Pattern --- 
  {"000102030405060708090a0b0c0d0e0f1011121314151617",
   "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
   "dda97ca4864cdfe06eaf70a0ec0d7191dda97ca4864cdfe06eaf70a0ec0d71913fe7286abde5f03943d5777020259626"},

  // --- All-Zeroes Test Vector ---
  {"000000000000000000000000000000000000000000000000",
   "00000000000000000000000000000000",
   "aae06992acbf52a3e8f4a96ec9300bd702bb292527e726fd51eb29894d6f0aad"},

  // --- Asimmetric Vector ---
  {"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
  "6bc1bee22e409f96e93d7e117393172a11223344",
  "bd334f1d6e45f25ff712a214571fa5cc682c249d62ad645ed89747d9e6f6c914"}
};


int main(){
  cout << "START OF THE TEST OF THE LIBRARY (AES-192 EBC)" << endl;
  
  int passed = 0;
  int failed = 0;

  for (int i = 0; i < n_tests; i++){
    Key key = Key::from_hex(tests[i].key);
    key.expand();

    Bytearray plain = Bytearray::from_hex(tests[i].plain);
    string cipher = tests[i].cipher;

    Bytearray my_cipher = encrypt_aes(plain, key);
    
    Bytearray my_decipher = decrypt_aes(my_cipher, key);

    bool round_error = false;

    if (my_cipher.hex() != cipher){
      cout << "Encrypt error in test number [" << i << "] -> Expected: " << cipher << " | Calculated: " << my_cipher.hex() << endl;
      round_error = true;
    }
    
    if (aes_functions::basic_hex(my_decipher) != tests[i].plain){
      cout << "Decrypt error in test number [" << i << "] -> Expected: " << tests[i].plain << " | Calculated: " << aes_functions::basic_hex(my_decipher) << endl;
      round_error = true;
    }

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