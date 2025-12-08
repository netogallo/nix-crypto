#pragma once

#include <nix/expr/primops.hh>
#include <rust/cxx.h>

#include "nix-crypto/src/cxx_bridge.rs.h"
//extern "C" {
//  int rust_add(int a, int b);
//}
//

struct CryptoNix;

class CryptoNixPrimops {
  public:
  CryptoNixPrimops();
  ~CryptoNixPrimops();

  std::string openssl_public_key_pem(std::string& key_type, std::string& key_identity);

  private:
  nix::RegisterPrimOp age;
  nix::RegisterPrimOp openssl;
  CryptoNix* cryptoNix;
};

void init_primops();
void destroy_primops();
