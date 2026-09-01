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
  {"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
   "000102030405060708090a0b0c0d0e0f",
   "6bc1bee22e409f96e93d7e117393172a",
   "4f021db243bc633d7178183a9fa071e8a647f1643b94812a175a13c8fa2014b2",},

  {"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
   "4f021db243bc633d7178183a9fa071e8",
   "ae2d8a571e03ac9c9eb76fac45af8e51",
   "b4d9ada9ad7dedf4e5e738763f69145ac81ca99c3a1e883fa8d834316a2275ec",},

  {"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
   "b4d9ada9ad7dedf4e5e738763f69145a",
   "30c81c46a35ce411e5fbc1191a0a52ef",
   "571b242012fb7ae07fa9baac3df102e0c54fcbc6db7424cb268f588f83292023",},

  {"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
   "571b242012fb7ae07fa9baac3df102e0",
   "f69f2445df4f9b17ad2b417be66c3710",
   "08b0e27988598881d920a9e64f5615cd612ccd79224b350935d45dd6a98f8176",},
    
  // --- Recurring Pattern --- 
  {"000102030405060708090a0b0c0d0e0f0001020304050607",
   "73bed6b8e3c1743b7116e69e22229516",
   "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
   "e52e0b944abf4cf5f7ba43b6f48f2423755208b608df2c006db0021aba2c9c823de85e0acfbe31986b4f231a9edfa8b4"},

  // --- All-Zeros Test Vector ---
  {"000000000000000000000000000000000000000000000000",
   "00000000000000000000000000000000",
   "00000000000000000000000000000000",
   "aae06992acbf52a3e8f4a96ec9300bd71045be567103016ac50b21b86fc5457e"},

  //  --- Asimmetric Vector ---
  {"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
   "000102030405060708090a0b0c0d0e0f",
  "6bc1bee22e409f96e93d7e117393172a11223344",
  "4f021db243bc633d7178183a9fa071e81533825ee1153ae9bda315867a9a890b"}
};


int main(){
  cout << "START OF THE TEST OF THE LIBRARY (AES-192 CBC)" << endl;
  
  int passed = 0;
  int failed = 0;

  for (int i = 0; i < n_tests; i++){
    Key key = Key::from_hex(tests[i].key);
    key.expand();

    Bytearray plain = Bytearray::from_hex(tests[i].plain);
    Bytearray iv = Bytearray::from_hex(tests[i].iv);
    string cipher = tests[i].cipher;

    Bytearray my_cipher = encrypt_aes(plain, key, iv);
    
    aes_types::ilist my_decipher = decrypt_aes(my_cipher, key, iv);

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