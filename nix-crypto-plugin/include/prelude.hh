#pragma once

#include <nix/expr/primops.hh>
#include <nix/cmd/common-eval-args.hh>
#include <nix/expr/eval-settings.hh>
#include <nix/fetchers/filtering-source-accessor.hh>
#include <nix/store/globals.hh>
#include <nix/util/configuration.hh>
#include <nix/util/config-global.hh>
#include <rust/cxx.h>

struct CxxNixAttrs;

/// @breif Lookup the given key in a nix attribute set and return as a rust String if found.
///
/// This function is meant to serve as a safe lookup. In absence of Maybes in hte
/// cxx library, a rust vector is returned which either has a single item or
/// is empty.
rust::Vec<rust::String> tryGetString(nix::EvalState& state, const nix::PosIdx pos, const std::string& key, nix::Value& attrs);

void toNixAttrs(nix::EvalState&, const nix::PosIdx, const CxxNixAttrs&, nix::Value&);
