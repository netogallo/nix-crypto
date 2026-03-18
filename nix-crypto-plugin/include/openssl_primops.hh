#pragma once
#include "nix_crypto_plugin/include/prelude.hh"

/// @breif Registers the openssl primos to the nix builtins by creating
///        a new attribute set under the crypto attribute set.
void primop_openssl(nix::EvalState& state, const nix::PosIdx _pos, nix::Value** _args, nix::Value& result);
