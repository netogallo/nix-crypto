#include "nix-crypto/include/nix_crypto.hh"
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

static OpensslPrivateKeyIdentity openssl_get_private_key_identity(
    EvalState& state,
    const PosIdx pos,
    Value& key_args
) {

    state.forceAttrs(key_args, pos, "while evaluating the openssl key args passed to builtins.openssl.public-key-pem");

    auto key_type = state.forceStringNoCtx(
        *state.getAttr(
            state.symbols.create("key-type"),
            key_args.attrs(),
            "in the openssl key parameters"
        )->value,
        pos,
        "while reading the 'key-type' parameter"
    );

    auto key_id = state.forceStringNoCtx(
        *state.getAttr(
            state.symbols.create("key-identity"),
            key_args.attrs(),
            "in the openssl key parameters"
        )->value,
        pos,
        "while reading the 'key-identity' parameter"
    );

    return { key_type.data(), key_id.data() };
}

static void primop_openssl_public_key_pem(EvalState& state, const PosIdx pos, Value** args, Value& result) {

    try {
        auto pem = primops->openssl_public_key_pem(
            std::move(openssl_get_private_key_identity(state, pos, *args[0]))
        );
        result.mkString(pem);
    } catch (rust::Error& e) {
        state.error<EvalError>(e.what())
            .atPos(pos)
            .debugThrow();
    }
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
    , cryptoNixSettings()
    , registerCryptoNixSettings(&cryptoNixSettings) {}

rust::Box<CryptoNix>& CryptoNixPrimops::cryptoNix() noexcept {

    if(!cryptoNixPtr) {
        cryptoNixPtr = std::make_unique<rust::Box<CryptoNix>>(
            cryptonix_with_settings(cryptoNixSettings.extraCryptoNixArgs)
        );
    }

    return *cryptoNixPtr;
}

std::string CryptoNixPrimops::openssl_public_key_pem(OpensslPrivateKeyIdentity&& key_identity) {

    return std::string(
        cryptoNix()->cxx_openssl_private_key(key_identity)->public_pem().c_str()
    );
}

CryptoNixPrimops::~CryptoNixPrimops() {}

void init_primops() {
    primops = std::make_unique<CryptoNixPrimops>();
}

void destroy_primops() {
    primops.reset();
}
