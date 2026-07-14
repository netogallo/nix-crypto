#include "nix_crypto_plugin/include/prelude.hh"

#include <format>
#include <stdexcept>

#include "nix_crypto_plugin/src/cxx_bridge.rs.h"

using namespace nix;

rust::Vec<rust::String> tryGetString(EvalState& state, const PosIdx pos, const std::string& key, Value& attrs) {

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

void toNixAttrs(
    nix::EvalState& state,
    const nix::PosIdx pos,
    const CxxNixAttrs& rustAttrs,
    Value& result
) {

    rust::Vec<rust::String> keys = rustAttrs.get_keys();
    nix::BindingsBuilder builder = state.buildBindings(keys.size());

    for(auto& key : keys) {

        auto keyS = state.symbols.create(key.c_str());

        if(
            auto mInt = rustAttrs.try_get_int(key);
            mInt.size() == 1
        ) {
            builder.alloc(keyS, pos).mkInt(mInt[0]);
        }
        else if(
            auto mString = rustAttrs.try_get_str(key);
            mString.size() == 1
        ) {
            builder.alloc(keyS, pos).mkString(
                std::string(mString[0].c_str())
            );
        }
        else if(
            auto mAttrs = rustAttrs.try_get_attrs(key);
            mAttrs.size() == 1
        ) {
            auto* value = state.allocValue();
            toNixAttrs(state, pos, mAttrs[0], *value);
            builder.insert(
                keyS,
                value,
                pos
            );
        }
        else {
            throw std::runtime_error(
                std::format("The key '{}' was declared but holds no value. This is a bug, aborting!", key.c_str())
            );
        }
    }

    result.mkAttrs(builder);
}
