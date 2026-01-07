#pragma once

#include <nix/expr/primops.hh>
#include <nix/cmd/common-eval-args.hh>
#include <nix/expr/eval-settings.hh>
#include <nix/fetchers/filtering-source-accessor.hh>
#include <nix/store/globals.hh>
#include <nix/util/configuration.hh>
#include <nix/util/config-global.hh>
#include <rust/cxx.h>

#include "nix-crypto/src/cxx_bridge.rs.h"

struct CryptoNix;

struct ExtraBuiltinsSettings : nix::Config {
  nix::Setting<std::string> extraCryptoNixArgs{
    this,
    "",
    "extra-cryptonix-args",
    "The configuration parameters for CyrptoNix."
  };
};

class CryptoNixPrimops {
  public:
  CryptoNixPrimops();
  ~CryptoNixPrimops();

  std::string openssl_public_key_pem(OpensslPrivateKeyIdentity&& key_identity);
  std::string opensslX509Pem(X509BuildParams&& buildParams);

  private:
  //nix::RegisterPrimOp age;
  //nix::RegisterPrimOp openssl;
  nix::RegisterPrimOp crypto;
  ExtraBuiltinsSettings cryptoNixSettings;
  nix::GlobalConfig::Register registerCryptoNixSettings;

  // This looks wrong at first glance as the rust::Box is already
  // a smart pointer so there is no need to wrap inside another smart
  // pointer. However, the settings passed to nix (via the --option xxx)
  // are not available at this point, therefore CryptoNix cannot be
  // initialized. Since rust::Box cannot be null/empty and cxx does not
  // (yet) expose option types, a c++ smart pointer is used for the sole
  // purpose of delyaing the initialization of this value until
  // the first usage of cryptonix.
  std::unique_ptr<rust::Box<CryptoNix>> cryptoNixPtr;

  rust::Box<CryptoNix>& cryptoNix() noexcept;
};

void init_primops();
void destroy_primops();
