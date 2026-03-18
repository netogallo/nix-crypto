/**
  The test runner for nix-crypto.

  Accepts the following arguments:
  - `pkgs`: the nixpkgs package set.
  - `nix-crypto-service`: either a store path string to the
    `nix-crypto-service` binary (prod), or a plain string path to the
    dev binary (e.g. `"$PWD/target/debug/nix-crypto-service"`).
*/
{
  pkgs,
  nix-crypto-service,
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
        then id
        else trace-force debug
      ;
    in
      if cond
      then trace-force output result
      else trace-force output (trace-with-debug result)
  ;

  /**
    Construct a test which passes if a nix expression evaluates to `true`.
    Otherwise fail with the given `message` argument.
    Although the test happens entirely in nix code, the outcome
    of the test will be a script.
  */
  write-unit-test = { name, test-script }:
    pkgs.writeScript
    name
    test-script
  ;

  test-nix-expression = { name, cond, message, debug ? null }:
  let
    result-success =
      ''
      echo -e "\t✓ ${name}"
      exit 0
      ''
    ;
    result-failure =
      ''
      echo -e "\t✗ ${name}"
      echo -e "\t  Error: ${message}"
      exit 1
      ''
    ;
    result =
      if cond
      then result-success
      else result-failure
    ;
    test-script =
      if debug == null
      then result
      else builtins.trace debug result
    ;
  in
    write-unit-test { inherit name test-script; }
  ;

  /**
    Wrap a bash script as a test. The script is run in a subshell;
    success and failure are reported with a ✓/✗ prefix.
    The script should exit with a non-zero status on failure.
  */
  test-bash-script = { name, script }:
    pkgs.writeScript
    name
    ''
    if (${script}); then
      echo -e "\t✓ ${name}"
      exit 0
    else
      echo -e "\t✗ ${name}"
      exit 1
    fi
    ''
  ;

  /**
    Construct the assertion library for a given test `name`.

    Available assertions:
    - `_assert <cond> <message>`: assert a nix boolean expression.
    - `_assert.is-string <value>`: assert a value is a string.
    - `_assert.is-int <value>`: assert a value is an int.
    - `_assert.strings.has-prefix <prefix> <value>`: assert a string has a prefix.
    - `_assert.bash-script <script>`: run a bash script as a test. The `STORE`
      environment variable is available in the script and points to the sled
      store used by the nix-crypto plugin.
  */
  _assert = { name }:
    let
      assert-main = { cond, message, debug ? null }:
        let
          context = { inherit name cond message debug; };
        in
          test-nix-expression context
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
        bash-script = script:
          test-bash-script { inherit name script; }
        ;
        __functor = self: cond: message: assert-main { inherit cond message; };
      }
  ;

  run-test = name: test:
  let
    context = {
      _assert = _assert { inherit name; };
    };
  in
    test context
  ;

  /**
    Run all tests in an attribute set, returning a shell script fragment
    that invokes each test and sets FAILURE=1 if any test fails.
  */
  run-tests = tests:
  let
    test-outcome = name: test:
      ''
      if ! ${run-test name test}; then
        echo "Failure"
        FAILURE=1
      fi
      ''
    ;
    test-outcomes =
      lib.attrValues (
        lib.mapAttrs test-outcome tests
      )
    ;
  in
    lib.concatStringsSep "\n\n" test-outcomes
  ;

  /**
    Import and run a test suite file, passing `pkgs` and `nix-crypto-service`
    as context.
  */
  run-suite = suite:
  let
    suite-context = { inherit pkgs nix-crypto-service; };
    suite-tests = import suite suite-context;
  in
    ''
    echo 'Suite: "${suite}"'
    ${run-tests suite-tests}
    echo -e "\n"
    ''
  ;

  /**
    Produce a `writeScript` derivation that runs all suites and
    exits with a non-zero status if any test fails.
  */
  run-suites = suites:
  let
    test-suites =
      lib.concatStringsSep "\n\n" (lib.map run-suite suites);
  in
    pkgs.writeScriptBin
      "nix-crypto-test-outcome"
      ''
      FAILURE=0
      ${test-suites}
      exit $FAILURE
      ''
  ;
in
  run-suites [
    ./openssl.nix
  ]
