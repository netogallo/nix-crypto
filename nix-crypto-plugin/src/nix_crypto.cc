#include <format>

#include "nix_crypto_plugin/include/nix_crypto.hh"
#include "nix_crypto_plugin/src/cxx_bridge.rs.h"

using namespace nix;

static std::unique_ptr<CryptoNixPrimops> primops = std::make_unique<CryptoNixPrimops>();

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
        auto pem = primops->opensslPublicKeyPem(
            std::move(openssl_get_private_key_identity(state, pos, *args[0]))
        );
        result.mkString(pem);
    } catch (rust::Error& e) {
        state.error<EvalError>(e.what())
            .atPos(pos)
            .debugThrow();
    }
}

static rust::Vec<rust::String> tryGetString(EvalState& state, const PosIdx pos, const std::string& key, Value& attrs) {

    auto attr = attrs.attrs()->get(state.symbols.create(key));

    if(!attr || !attr->value) {
        return {};
    }

    Value& value = *attr->value;
    state.forceValue(value, pos);

    // Nulls are treated as the attribute being absent
    if(value.type() == nNull) {
        return {};
    }

    std::string result (
        state.forceString(
            value,
            pos,
            std::format("while reading the value of the attribute '{}'", key)
        ).data()
    );

    return { rust::String(std::move(result)) };
}

const std::string K_KEY_USAGE_CRITICAL = "critical";
const std::string K_KEY_USAGE_CRL_SIGN = "crl-sign";
const std::string K_KEY_USAGE_KEY_CERT_SIGN = "key-cert-sign";

static rust::Vec<X509KeyUsage> tryGetKeyUsage(EvalState& state, const PosIdx pos, const std::string& key, Value& attrs) {

    auto attr = attrs.attrs()->get(state.symbols.create(key));

    if(!attr || !attr->value) {
        return {};
    }

    auto& value = *attr->value;
    state.forceValue(value, pos);

    // Nulls are also treated as the attribute being absent
    if(value.type() == nNull) {
        return {};
    }

    state.forceAttrs(
        value,
        pos,
        std::format("expected the 'x509 key constraints' extension to be an attribute set as the attribute '{}' of the parameters.", key)
    );

    auto criticalAttr = value.attrs()->get(state.symbols.create(K_KEY_USAGE_CRITICAL));
    bool critical = false;

    if(criticalAttr) {
        critical = state.forceBool(
            *criticalAttr->value,
            pos,
            std::format("the value of the '{}' attribute provided for the 'x509 key usage' must be a bool", K_KEY_USAGE_CRITICAL)
        );
    }

    auto keyCertSignAttr = value.attrs()->get(state.symbols.create(K_KEY_USAGE_KEY_CERT_SIGN));
    bool keyCertSign = false;

    if(criticalAttr) {
        keyCertSign = state.forceBool(
            *criticalAttr->value,
            pos,
            std::format("the value of the '{}' attribute provided for the 'x509 key usage' must be a bool", K_KEY_USAGE_KEY_CERT_SIGN)
        );
    }

    auto crlSignAttr = value.attrs()->get(state.symbols.create(K_KEY_USAGE_CRL_SIGN));
    auto crlSign = false;

    if(crlSignAttr) {
        crlSign = state.forceBool(
            *crlSignAttr->value,
            pos,
            std::format("the value of the '{}' attribute provided for the 'x509 key usage' must be a bool", K_KEY_USAGE_CRL_SIGN)
        );
    }

    return { { .critical = critical, .key_cert_sign = keyCertSign, .crl_sign = crlSign} };
}

const std::string K_BUILD_PARAMS_CRITICAL = "critical";
const std::string K_BUILD_PARAMS_CA = "ca";

static rust::Vec<X509BasicConstraints> tryGetBasicConstraints(EvalState& state, const PosIdx pos, const std::string& key, Value& attrs) {

    auto attr = attrs.attrs()->get(state.symbols.create(key));

    if(!attr) {
        return {};
    }

    auto& value = *attr->value;
    state.forceValue(value, pos);

    // Nulls are treated as if the value were absent
    if (value.type() == nNull) {
        return {};
    }

    state.forceAttrs(
        value,
        pos,
        std::format("expected the 'x509 basic constraints' extension, provided under the attribute {}, to be an attribute set.", key)
    );

    auto criticalAttr = value.attrs()->get(state.symbols.create(K_BUILD_PARAMS_CRITICAL));
    bool critical = false;

    if(criticalAttr) {
        critical = state.forceBool(
            *criticalAttr->value,
            pos,
            std::format("the value of the '{}' attribute provided for the 'x509 basic constraints' must be a bool", K_BUILD_PARAMS_CRITICAL)
        );
    }

    auto caAttr = value.attrs()->get(state.symbols.create(K_BUILD_PARAMS_CA));
    bool ca = false;

    if(caAttr) {
        ca = state.forceBool(
            *caAttr->value,
            pos,
            std::format("the value of the '{}' attribute provided for the 'x509 basic constraints' must be a bool", K_BUILD_PARAMS_CA)
        );
    }

    return { X509BasicConstraints { .critical = critical, .ca = ca } };
}
    

static rust::Vec<X509NameItem> asX509Name(EvalState& state, const PosIdx pos, Value& attrs) {

    state.forceAttrs(attrs, pos, "expected the 'x509 name' to be represented as an attribute set of strings");
    rust::Vec<X509NameItem> result;
    result.reserve(attrs.attrs()->size());

    for(auto attr : *attrs.attrs()) {
        auto attrName = rust::String(std::string(state.symbols[attr.name]));
        auto attrValue = rust::String(
            state.forceString(
                *attr.value,
                pos,
                std::format("expected the attributes of the 'X509 name' to be strings. The attribute '{}' is not a string.", attrName.data())
            ).data()
        );
        result.emplace_back(attrName, attrValue);
    }

    return std::move(result);
}

const std::string K_SUBJECT_PUBLIC_KEY = "subject-public-key";
const std::string K_SIGNING_PRIVATE_KEY_IDENTITY = "signing-private-key-identity";
const std::string K_SUBJECT_NAME = "subject-name";
const std::string K_ISSUER_NAME = "issuer-name";
const std::string K_SERIAL = "serial";
const std::string K_START_DATE = "start-date";
const std::string K_EXPIRY_DATE = "expiry-date";
const std::string K_BASIC_CONSTRAINTS = "basic-constraints";
const std::string K_KEY_USAGE = "key-usage";

static X509BuildParams toX509Params(EvalState& state, const PosIdx pos, Value& params) {

    state.forceAttrs(params, pos, "while evaluating the openssl build parameters to build an X509 certificate.");

    auto subjectPublicKey = tryGetString(state, pos, K_SUBJECT_PUBLIC_KEY, params);
    auto signingKey = openssl_get_private_key_identity(
        state,
        pos,
        *state.getAttr(
            state.symbols.create(K_SIGNING_PRIVATE_KEY_IDENTITY),
            params.attrs(),
            std::format("while accessing the '{}' attribute.", K_SIGNING_PRIVATE_KEY_IDENTITY)
        )->value
    );
    auto subjectName =
        asX509Name(
            state,
            pos,
            *state.getAttr(
                state.symbols.create(K_SUBJECT_NAME),
                params.attrs(),
                "A 'x509 subject name' must be provided as a attribute set of strings"
            )->value
        );
    auto issuerName =
        asX509Name(
            state,
            pos,
            *state.getAttr(
                state.symbols.create(K_ISSUER_NAME),
                params.attrs(),
                "A 'x509 issuer name' must be provided as a attribute set of strings"
            )->value
        );

    int serial =
        state.forceInt(
            *state.getAttr(
                state.symbols.create(K_SERIAL),
                params.attrs(),
                "A 'x509 serial' must be provided as an integer"
            )->value,
            pos,
            std::format("A 'X509' serial must be provided as an int under the attribute {}", K_SERIAL)
        ).value;

    auto startDate =
        state.forceString(
            *state.getAttr(
                state.symbols.create(K_START_DATE),
                params.attrs(),
                "A starting date must be provided as a string formatted using the 'RFC 3339' standard."
            )->value,
            pos,
            std::format("A starting date must be provided as a string formatted using the 'RFC 3339' standard under the '{}' attribute", K_START_DATE)
        ).data();

    auto expiryDate =
        state.forceString(
            *state.getAttr(
                state.symbols.create(K_EXPIRY_DATE),
                params.attrs(),
                "An expiry date must be provided as a string formatted using the 'RFC 3339' standard."
            )->value,
            pos,
            std::format("A expiry date must be provided as a string formatted using the 'RFC 3339' standard under the '{}' attribute", K_START_DATE)
        ).data();

    auto basicConstraints = tryGetBasicConstraints(state, pos, K_BASIC_CONSTRAINTS, params);

    auto keyUsage = tryGetKeyUsage(state, pos, K_KEY_USAGE, params);

    return {
        .subject_public_key = std::move(subjectPublicKey),
        .signing_private_key_identity = std::move(signingKey),
        .issuer_name = std::move(issuerName),
        .subject_name = std::move(subjectName),
        .serial = serial,
        .start_date = rust::String(startDate),
        .expiry_date = rust::String(expiryDate),
        .extension_key_usage = std::move(keyUsage),
        .extension_basic_constraints = std::move(basicConstraints)
    };
}

static void primop_openssl_x509_pem(EvalState& state, const PosIdx pos, Value** args, Value& result) {

    try {
        auto pem = primops->opensslX509Pem(
            toX509Params(state, pos, *args[0])
        );
        result.mkString(pem);
    } catch(rust::Error& e) {
        state.error<EvalError>(e.what())
            .atPos(pos)
            .debugThrow();
    }
}

constexpr const int OPENSSL_PRIMOPS_COUNT = 2;
constexpr const std::string K_X509_PEM = "x509-pem";

static void primop_openssl(EvalState& state, const PosIdx _pos, Value** _args, Value& result) {

    auto attrs = state.buildBindings(OPENSSL_PRIMOPS_COUNT);

    auto openssl_public_key_pem = state.symbols.create("public-key-pem");
    attrs.alloc(openssl_public_key_pem).mkPrimOp(new PrimOp {
        .name = "public-key-pem",
        .arity = 1,
        .fun = primop_openssl_public_key_pem
    });

    auto opensslX509Pem = state.symbols.create(K_X509_PEM);
    attrs.alloc(opensslX509Pem).mkPrimOp(new PrimOp { 
        .name = K_X509_PEM,
        .arity = 1,
        .fun = primop_openssl_x509_pem
    });

    result.mkAttrs(attrs);
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
        .arity = 0,
        .fun = primop_crypto
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

CryptoNixPrimops::~CryptoNixPrimops() {}

void init_primops() {}

void destroy_primops() {}
