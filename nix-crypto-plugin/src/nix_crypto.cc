#include <format>

#include "nix_crypto_plugin/include/nix_crypto.hh"
#include "nix_crypto_plugin/src/cxx_bridge.rs.h"

#include "nix_crypto_plugin/include/openssl_primops.hh"

using namespace nix;

std::unique_ptr<CryptoNixPrimops> primops = std::make_unique<CryptoNixPrimops>();

static void primop_add(EvalState & state, const PosIdx pos, Value ** args, Value & v) {

    auto x = state.forceInt(*args[0], pos, "while evaluating the devil").value;
    auto y = state.forceInt(*args[1], pos, "while evaluating god").value;
    auto result = rust_add(x, y);

    v.mkInt(result);
}

static void primop_age(EvalState& state, const PosIdx, Value **, Value & v) {
    auto attrs = state.buildBindings(1);

    auto sExec = state.symbols.create("add");
    attrs.alloc(sExec).mkPrimOp(new PrimOp {
        .name = "add",
        .args = {},
        .arity = 2,
        .doc = {},
        .fun = primop_add,
        .experimentalFeature = {},
    });

    v.mkAttrs(attrs);
}

#define CRYPTO_PRIMOPS_COUNT 2

static void primop_crypto(EvalState& state, const PosIdx pos, Value** args, Value& result) {
    auto attrs = state.buildBindings(CRYPTO_PRIMOPS_COUNT);

    Value& openssl = attrs.alloc(state.symbols.create("openssl"));
    primop_openssl(state, pos, args, openssl);

    Value& age = attrs.alloc(state.symbols.create("age"));
    primop_age(state, pos, args, age);

    result.mkAttrs(attrs);
}

CryptoNixPrimops::CryptoNixPrimops()
    : crypto({
        .name = "__crypto",
        .args = {},
        .arity = 0,
        .doc = {},
        .fun = primop_crypto,
        .experimentalFeature = {},
    })
    , cryptoNixSettings()
    , registerCryptoNixSettings(&cryptoNixSettings) {}

rust::Box<CxxNixCrypto>& CryptoNixPrimops::cryptoNix() noexcept {

    if(!cryptoNixPtr) {
        cryptoNixPtr = std::make_unique<rust::Box<CxxNixCrypto>>(
            nix_crypto_with_settings(cryptoNixSettings.extraCryptoNixArgs)
        );
    }

    return *cryptoNixPtr;
}

std::string CryptoNixPrimops::opensslPublicKeyPem(OpensslPrivateKeyIdentity&& key_identity) {

    return std::string(
        cryptoNix()->cxx_openssl_private_key(key_identity)->public_pem().c_str()
    );
}

std::string CryptoNixPrimops::opensslX509Pem(X509BuildParams&& buildParams) {

    return std::string(
        cryptoNix()->cxx_openssl_x509_certificate(buildParams)->public_pem().c_str()
    );
}

std::string CryptoNixPrimops::opensslExportDecryptableOpensslPkey(
    OpensslSymmetricKeyIdentity&& symmetric_key,
    OpensslPrivateKeyIdentity&& credential
) {
    return std::string(
        cryptoNix()->cxx_export_decryptable_openssl_pkey(symmetric_key, credential).c_str()
    );
}

CryptoNixPrimops::~CryptoNixPrimops() {}

void init_primops() {
}

void destroy_primops() {}
