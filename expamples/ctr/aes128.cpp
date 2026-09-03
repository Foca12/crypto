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
  {"2b7e151628aed2a6abf7158809cf4f3c",
   "6bc1bee22e409f96e93d7e117393172a",
   "874d6191b620e3261bef6864990db6ce",},

  {"2b7e151628aed2a6abf7158809cf4f3c",
   "ae2d8a571e03ac9c9eb76fac45af8e51",
   "9806f66b7970fdff8617187bb9fffdff",},

  {"2b7e151628aed2a6abf7158809cf4f3c",
   "30c81c46a35ce411e5fbc1191a0a52ef",
   "5ae4df3edbd5d35e5b4f09020db03eab",},

  {"2b7e151628aed2a6abf7158809cf4f3c",
   "f69f2445df4f9b17ad2b417be66c3710",
   "1e031dda2fbe03d1792170a0f3009cee",},
    
  // --- Recurring Pattern --- 
  {"000102030405060708090a0b0c0d0e0f",
   "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
   "6b10801b69c335150c1b73a933236fc2e92503c321815f2920148fc58c92d67c"},

  // --- All-Zeros Test Vector ---
  {"00000000000000000000000000000000",
   "00000000000000000000000000000000",
   "006a010e0f4777d7785292b285d04dce"},

  // --- Asimmetric Vector ---
  {"2b7e151628aed2a6abf7158809cf4f3c",
   "6bc1bee22e409f96e93d7e117393172a11223344",
   "5018129b679eb46f8c54d229306b65686cb8fdc4"}
};


int main(){
  cout << "START OF THE TEST OF THE LIBRARY (AES-128 CTR)" << endl;
  
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