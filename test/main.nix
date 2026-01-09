{
  pkgs,
  ...
}:
let
  inherit (pkgs) lib;
  id = x: x;
  success = { success = true; message = null; };
  fail = message: { success = false; inherit message; };
  trace-test = { name, cond, message, debug ? null }: result:
    let
      output =
        {
          test = name;
          status = if cond then "Ok" else "Failed";
        }
        // (if cond || message == null then {} else { inherit message; })
      ;
      trace-force = debug:
        if lib.all id (lib.attrValues (lib.mapAttrs (k: v: lib.typeOf k == lib.typeOf v) debug))
        then builtins.trace debug
        else builtins.trace debug
      ;
      trace-with-debug =
        if debug == null
        then (x: x)
        else trace-force debug
      ;
    in
      if cond
      then trace-force output result
      else trace-force output (trace-with-debug result)
  ;
  _assert = { name }:
    let
      assert-main = { cond, message, debug ? null }:
        let
          context = { inherit name cond message debug; };
        in
          if cond
          then trace-test context success
          else trace-test context (fail message)
      ;
    in
      {
        strings = with lib.strings; {
          has-prefix = prefix: value:
            assert-main {
              cond = (hasPrefix prefix value);
              message = "String expected to have the prefix '${prefix}'";
              debug = { inherit prefix value; };
            }
          ;
        };
        is-string = value:
          assert-main {
            cond = (lib.typeOf value == "string");
            message = "Assertion failed, value expected to be a string";
            debug = { inherit value; };
          }
        ;
        is-int = value:
          assert-main {
            cond = (lib.typeOf value == "int");
            message = "Assertion failed, value expecteed to be an int";
            debug = { inherit value; };
          }
        ;
        __functor = self: cond: message: assert-main { inherit cond message; };
      }
  ;
  run-test = name: test:
    let
      context = {
        _assert = _assert { inherit name; };
      };
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
