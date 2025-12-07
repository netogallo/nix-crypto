#pragma once

#include <nix/expr/primops.hh>
//extern "C" {
//  int rust_add(int a, int b);
//}
//

class CryptoNixPrimops {
  public:
  CryptoNixPrimops();

  private:
  nix::RegisterPrimOp age;
};

void init_primops();
void destroy_primops();
