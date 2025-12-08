#pragma once

#include <nix/expr/primops.hh>
#include <rust/cxx.h>

#include "nix-crypto/src/cxx_bridge.rs.h"

struct CryptoNix;

class CryptoNixPrimops {
  public:
  CryptoNixPrimops();
  ~CryptoNixPrimops();

  std::string openssl_public_key_pem(OpensslPrivateKeyIdentity&& key_identity);

  private:
  nix::RegisterPrimOp age;
  nix::RegisterPrimOp openssl;
  CryptoNix* cryptoNix;
};

void init_primops();
void destroy_primops();
