#pragma once

#include "message.hpp"
#include "..\bytearray\bytearray.hpp"

namespace crypto::sha
{
  Bytearray hash_sha256(Bytearray msg) {
    Sha256_message message = Sha256_message::divide_bytearray(msg);
    message.expand();
    return message.hash();
  }
} // namespace crypto::sha
