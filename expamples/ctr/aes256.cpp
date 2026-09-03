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
  {"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
  "6bc1bee22e409f96e93d7e117393172a",
  "601ec313775789a5b7a7f504bbf3d228",},

  {"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
  "ae2d8a571e03ac9c9eb76fac45af8e51",
  "f443e3ca4d62b59aca84e990cacaf5c5",},

  {"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
  "30c81c46a35ce411e5fbc1191a0a52ef",
  "2b0930daa23de94ce87017ba2d84988d",},

  {"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
  "f69f2445df4f9b17ad2b417be66c3710",
  "dfc9c58db67aada613c2dd08457941a6",},
    
  // --- Recurring Pattern --- 
  {"000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f",
   "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
   "57ede3e2770fa323fe1d266b04b1388b87a83d10b7e956c06c3ef4e8af1a010c"},

  // --- All-Zeros Test Vector ---
  {"0000000000000000000000000000000000000000000000000000000000000000",
   "0000000000000000000000000000000000000000000000000000000000000000",
   "f0b97e6cd082f055f99deb8d85b94cfb4429f37b072c0ab8b068c507bf9f55a3"},

  // --- Asimmetric Vector ---
  {"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
   "6bc1bee22e409f96e93d7e117393172a11223344",
   "720fed1e1e551ee43c6a62519dd24e42254d1a4d"}
};


int main(){
  cout << "START OF THE TEST OF THE LIBRARY (AES-256 CTR)" << endl;
  
  int passed = 0;
  int failed = 0;

  crypto::Bytearray iv = crypto::Bytearray::from_hex(test_iv);
  for (int i = 0; i < n_tests; i++){
    crypto::Bytearray key = crypto::Bytearray::from_hex(tests[i].key);

    crypto::Bytearray plain = crypto::Bytearray::from_hex(tests[i].plain);
    string cipher = tests[i].cipher;

    crypto::Bytearray my_cipher = crypto::aes::encrypt_aes(plain, key, iv, crypto::aes::CTR);
    
    crypto::Bytearray my_decipher = crypto::aes::decrypt_aes(my_cipher, key, iv, crypto::aes::CTR);

    bool round_error = false;

    if (my_cipher.hex() != cipher){
      cout << "Encrypt error in test number [" << i << "] -> Expected: " << cipher << " | Calculated: " << my_cipher.hex() << endl;
      round_error = true;
    }
    
    if (my_decipher.hex() != tests[i].plain){
      cout << "Decrypt error in test number [" << i << "] -> Expected: " << tests[i].plain << " | Calculated: " << my_decipher.hex() << endl;
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