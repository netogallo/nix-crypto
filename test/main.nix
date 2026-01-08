{
  pkgs,
  ...
}:
let
  inherit (pkgs) lib;
  id = x: x;
  success = { success = true; message = null; };
  fail = message: { success = false; inherit message; };
  assert-main = cond: message:
    if cond
    then success
    else fail message
  ;
  _assert = rec {
    is-string = value:
    assert-main
    (lib.typeOf value == "string")
    "Assertion failed, value expected to be a string"
  ;
    __functor = self: assert-main;
  };
  run-test = name: test:
    let
      context = { inherit _assert; };
      result = test context;
    in
      if !(lib.hasAttr "success" result)
      then throw ''
        The test is expected to produce a result. Use the functions
        from the '_assert' parameter to construct.
      ''
      else if result.success
      then true
      else throw result.message
  ;
  run-tests = tests:
    let
      results =
        lib.attrValues (
          lib.mapAttrs run-test tests
        )
      ;
    in
      lib.all id results
  ;
  run-suite = suite:
    let
      suite-context = {};
      suite-tests = import suite { inherit pkgs; };
    in
      run-tests suite-tests
  ;
  run-suites = suites:
    lib.all id (lib.map run-suite suites)
  ;
in
  run-suites [
    ./openssl.nix
  ]
