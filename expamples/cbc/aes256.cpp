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
  {"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
   "000102030405060708090a0b0c0d0e0f",
   "6bc1bee22e409f96e93d7e117393172a",
   "f58c4c04d6e5f1ba779eabfb5f7bfbd6485a5c81519cf378fa36d42b8547edc0"},

  {"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
   "f58c4c04d6e5f1ba779eabfb5f7bfbd6",
   "ae2d8a571e03ac9c9eb76fac45af8e51",
   "9cfc4e967edb808d679f777bc6702c7d3a3aa5e0213db1a9901f9036cf5102d2"},

  {"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
   "9cfc4e967edb808d679f777bc6702c7d",
   "30c81c46a35ce411e5fbc1191a0a52ef",
   "39f23369a9d9bacfa530e263042314612f8da707643c90a6f732b3de1d3f5cee"},

  {"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
   "39f23369a9d9bacfa530e26304231461",
   "f69f2445df4f9b17ad2b417be66c3710",
   "b2eb05e2c39be9fcda6c19078c6a9d1b3f461796d6b0d6b2e0c2a72b4d80e644"},
    
  // --- Recurring Pattern --- 
  {"000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f",
   "73bed6b8e3c1743b7116e69e22229516",
   "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
   "a7fb871942f83dc8115554cd4a576faea5304b298679d58e28af6fb781385947f1ce4a82fba9f051ee423312676aceb7"},

  // --- All-Zeros Test Vector ---
  {"0000000000000000000000000000000000000000000000000000000000000000",
   "00000000000000000000000000000000",
   "00000000000000000000000000000000",
   "dc95c078a2408989ad48a21492842087f3c003ddc4a7b8a94baedffc3d214c38"},

  // --- Asimmetric Vector ---
  {"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
   "000102030405060708090a0b0c0d0e0f",
   "6bc1bee22e409f96e93d7e117393172a11223344",
   "f58c4c04d6e5f1ba779eabfb5f7bfbd6187db1085a48498a313b21840b2d406b"}
};


int main(){
  cout << "START OF THE TEST OF THE LIBRARY (AES-256 CBC)" << endl;
  
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