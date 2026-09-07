#include <iostream>
#include "../../include/sha.hpp"
#include "../../include/bytearray.hpp"

using namespace std;

typedef struct {
  string plain;
  string hash;
} test;

constexpr size_t n_tests = 10;

const test tests[n_tests] = {
    // 1. Empty string ""
    { "",
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },

    // 2. Test "abc"
    { "616263",
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
    
    // 3. Test "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    { "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071",
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
    
    // 4. Test "a"
    { "61",
      "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb" },
    
    // 5. Test "message digest"
    { "6d65737361676520646967657374",
      "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650" },
    
    // 6. Test "abcdefghijklmnopqrstuvwxyz"
    { "6162636465666768696a6b6c6d6e6f707172737475767778797a",
      "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73" },
    
    // 7. Test "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    { "4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839",
      "db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0" },
    
    // 8. Test "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
    { "3132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930",
      "f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e" },
    
    // 9. Regular pattern
    { "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd" },
    
    // 10. Single byte
    { "ff",
      "a8100ae6aa1940d0b663bb31cd466142ebbdbd5187131b92d93818987832eb89" }
};


int main(){
  cout << "START OF THE TEST OF THE LIBRARY (SHA 256)" << endl;
  
  int passed = 0;
  int failed = 0;

  for (size_t i = 0; i < n_tests; i++){
    crypto::Bytearray plain = crypto::Bytearray::from_hex(tests[i].plain);
    crypto::Bytearray hash = crypto::sha::hash_sha256(plain);

    bool round_error = false;

    if (hash.hex() != tests[i].hash){
      cout << "Hash error in test number [" << i << "] -> Expected: " << tests[i].hash << " | Calculated: " << hash.hex() << endl;
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