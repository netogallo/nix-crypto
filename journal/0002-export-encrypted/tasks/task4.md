The objective of this task is to take the rust `NixAttrs` type defined in `nix-crypto-core/src/support.rs` and expose it as a CXX opaque type in the `nix-crypto-plugin/src/cxx_bridge.rs` file. The type is defined in a different crate, so a wrapper type called `CxxNixAttrs` needs to be defined in `nix-crypto-plugin/src/cxx_api/data.rs` which will expose member functions with a C++ friendly signature.

The following member functions are needed:

```
/// Get the keys that exist in the `NixAttrs` value.
get_keys : CxxNixAttrs -> Vec<String>

/// Try looking up the key as an int.
try_get_int(key: &String, result: &'mut u32) -> Bool

/// Try looking up the key as a String
try_get_str(key: &String, result: mut Box<String>) -> Bool

/// Try looking up the key as Attrs
try_get_attrs(key: &String, result: mut Box<CxxNixAttrs>) -> Bool
```

Finally, modify the `nix-crypto-plugin/src/cxx_bridge.rs` file such that theese new functionare exposed to C++.
