#include "nix_crypto_plugin/include/prelude.hh"

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
