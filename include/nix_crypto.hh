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

  private:
  nix::RegisterPrimOp age;
  CryptoNix* cryptoNix;
};

void init_primops();
void destroy_primops();
