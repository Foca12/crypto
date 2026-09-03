#include <iostream>
#include "../../include/aes.hpp"
#include "../../include/bytearray.hpp"

using namespace std;

typedef struct {
  string key;
  string iv;
  string plain;
  string cipher;
} test;

constexpr size_t n_tests = 7;

const test tests[n_tests] = {
  // --- NIST Vectors ---
  {"2b7e151628aed2a6abf7158809cf4f3c",
   "000102030405060708090a0b0c0d0e0f",
   "6bc1bee22e409f96e93d7e117393172a",
   "7649abac8119b246cee98e9b12e9197d8964e0b149c10b7b682e6e39aaeb731c",},

  {"2b7e151628aed2a6abf7158809cf4f3c",
   "7649abac8119b246cee98e9b12e9197d",
   "ae2d8a571e03ac9c9eb76fac45af8e51",
   "5086cb9b507219ee95db113a917678b255e21d7100b988ffec32feeafaf23538",},

  {"2b7e151628aed2a6abf7158809cf4f3c",
   "5086cb9b507219ee95db113a917678b2",
   "30c81c46a35ce411e5fbc1191a0a52ef",
   "73bed6b8e3c1743b7116e69e22229516f6eccda327bf8e5ec43718b0039adceb",},

  {"2b7e151628aed2a6abf7158809cf4f3c",
   "73bed6b8e3c1743b7116e69e22229516",
   "f69f2445df4f9b17ad2b417be66c3710",
   "3ff1caa1681fac09120eca307586e1a78cb82807230e1321d3fae00d18cc2012",},
    
  // --- Recurring Pattern --- 
  {"000102030405060708090a0b0c0d0e0f",
   "73bed6b8e3c1743b7116e69e22229516",
   "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
   "4c40dabd87bfa06fd8f951f01f29a1d6b43e61fe12573d99261110668b4262f452ee9c1b90ebbb3fc72e5e0c46e7aa08"},

  // --- All-Zeros Test Vector ---
  {"00000000000000000000000000000000",
   "00000000000000000000000000000000",
   "00000000000000000000000000000000",
   "66e94bd4ef8a2c3b884cfa59ca342b2e9434dec2d00fdac765f00c0c11628cd1"},

  // --- Asimmetric Vector ---
  {"2b7e151628aed2a6abf7158809cf4f3c",
   "000102030405060708090a0b0c0d0e0f",
   "6bc1bee22e409f96e93d7e117393172a11223344",
   "7649abac8119b246cee98e9b12e9197dacb66f623bf55c7737e8941e1957565b"}
};


int main(){
  cout << "START OF THE TEST OF THE LIBRARY (AES-128 CBC)" << endl;
  
  int passed = 0;
  int failed = 0;

  for (int i = 0; i < n_tests; i++){
    Bytearray key = Bytearray::from_hex(tests[i].key);


    Bytearray plain = Bytearray::from_hex(tests[i].plain);
    Bytearray iv = Bytearray::from_hex(tests[i].iv);
    string cipher = tests[i].cipher;

    Bytearray my_cipher = encrypt_aes(plain, key, iv, CBC);
    
    aes_types::ilist my_decipher = decrypt_aes(my_cipher, key, iv, CBC);

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