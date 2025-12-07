#include <nix/cmd/common-eval-args.hh>
#include <nix/expr/eval-settings.hh>
#include <nix/expr/primops.hh>
#include <nix/fetchers/filtering-source-accessor.hh>
#include <nix/store/globals.hh>
#include <nix/util/configuration.hh>
#include <nix/util/config-global.hh>


//#include "nix-crypto.hh"
#include "nix-crypto/src/lib.rs.h"

using namespace nix;

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

CryptoNixPrimops::CryptoNixPrimops()
    : age({
      .name = "__age",
      .arity = 0,
      .fun = primop_age,
    })
    {}

std::unique_ptr<CryptoNixPrimops> primops;

void init_primops() {
    primops = std::make_unique<CryptoNixPrimops>();
}

void destroy_primops() {
    primops.reset();
}
