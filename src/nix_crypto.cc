#include <nix/cmd/common-eval-args.hh>
#include <nix/expr/eval-settings.hh>
#include <nix/expr/primops.hh>
#include <nix/fetchers/filtering-source-accessor.hh>
#include <nix/store/globals.hh>
#include <nix/util/configuration.hh>
#include <nix/util/config-global.hh>


#include "nix-crypto/src/cxx_bridge.rs.h"

using namespace nix;

std::unique_ptr<CryptoNixPrimops> primops;

static void primop_add(EvalState & state, const PosIdx pos, Value ** args, Value & v) {

    auto x = state.forceInt(*args[0], pos, "while evaluating the devil").value;
    auto y = state.forceInt(*args[1], pos, "while evaluating god").value;
    auto result = rust_add(x, y);

    v.mkInt(result);
}

static void primop_age(EvalState & state, const PosIdx pos, Value ** _args, Value & v) {
    auto attrs = state.buildBindings(1);

    auto sExec = state.symbols.create("add");
    attrs.alloc(sExec).mkPrimOp(new PrimOp {
        .name = "add",
        .arity = 2,
        .fun = primop_add,
    });

    v.mkAttrs(attrs);
}

static void primop_openssl_public_key_pem(EvalState& state, const PosIdx pos, Value** args, Value& result) {

    auto key_args = args[0];
    state.forceAttrs(*key_args, pos, "while evaluating the openssl key args passed to builtins.openssl.public-key-pem");

    std::string key_type(
        state.forceStringNoCtx(
            *state.getAttr(
                state.symbols.create("key-type"),
                key_args->attrs(),
                "in the openssl key parameters"
            )->value,
            pos,
            "while reading the 'key-type' parameter"
        )
    );

    std::string key_id(
        state.forceStringNoCtx(
            *state.getAttr(
                state.symbols.create("key-identity"),
                key_args->attrs(),
                "in the openssl key parameters"
            )->value,
            pos,
            "while reading the 'key-identity' parameter"
        )
    );

    auto pem = primops->openssl_public_key_pem(key_type, key_id);
    result.mkString(pem);
}

static void primop_openssl(EvalState& state, const PosIdx _pos, Value** _args, Value& result) {

    auto attrs = state.buildBindings(1);
    auto openssl_public_key_pem = state.symbols.create("public-key-pem");
    attrs.alloc(openssl_public_key_pem).mkPrimOp(new PrimOp {
        .name = "public-key-pem",
        .arity = 1,
        .fun = primop_openssl_public_key_pem
    });

    result.mkAttrs(attrs);
}

CryptoNixPrimops::CryptoNixPrimops()
    : age({
      .name = "__age",
      .arity = 0,
      .fun = primop_age,
    })
    , openssl({
        .name = "__openssl",
        .arity = 0,
        .fun = primop_openssl
    })
    , cryptoNix(cryptonix_with_directory("")) {}

std::string CryptoNixPrimops::openssl_public_key_pem(
    std::string& key_type,
    std::string& key_identity) {

    return std::string(
        cryptoNix->cxx_openssl_private_key(key_type, key_identity)->public_pem().c_str()
    );
}

CryptoNixPrimops::~CryptoNixPrimops() {
    cryptonix_destroy(cryptoNix);
}

void init_primops() {
    primops = std::make_unique<CryptoNixPrimops>();
}

void destroy_primops() {
    primops.reset();
}
