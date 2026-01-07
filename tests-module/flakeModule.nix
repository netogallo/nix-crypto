
{ self, lib, flake-parts-lib, ... }:
let
  inherit (flake-parts-lib)
    mkPerSystemOption;
  inherit (lib)
    mkOption
    types;
in
{
  options.perSystem = mkPerSystemOption ({ pkgs, config, ...}: 
  let
    inherit (pkgs) lib;
    test-type = types.mkOptionType {
      name = "test-type";
      description = ''
        A unit test. It should be a function accepting a test context and
        should produce a test result which is an attribute set with the
        following attribtues:
        - success: A boolean value indicating if the test succeeded or failed.
        - message: A string with context regarding the 'success' value.
      '';
      check = test: builtins.typeOf test == "lambda";
      typeMerge = null;
    };
    test-submodule = types.submodule {
      options = {
        test = mkOption {
          type = test-type;
          description = ''
            The unit test to be carried out.
          '';
        };
      };
    };
    runTest = name: test:
    let
      result = test.test {};
    in
      if result.success
      then
      ''
        echo -e "\nTest: ${name}"
        echo -e "\tstatus: Ok"
        echo -e "\tmessage: ${result.message}"
      ''
      else
      ''
        echo -e "\nTest: ${name}"
        echo -e "\tstatus: Failed"
        echo -e "\tmessage: ${result.message}"
        exit 1
      ''
    ;
    runTests = tests:
    let
      results = lib.mapAttrs runTest tests;
    in
    pkgs.runCommand "cryptonix-tests" {} ''
        echo "======================="
        echo "running cryptonix tests"
        echo "======================="

        ${lib.concatStringsSep "\n" (lib.attrValues results)}
        touch $out
      ''
    ;
  in
    {
      options.tests = mkOption {
        description = ''
          An attribute set containing the test context. Each attribute is considered
         a individual test.
        '';
        type = types.attrsOf test-submodule;
        default = {};
      };
      #config.checks."cryptonix-tests" = runTests config.tests;
      config.checks."cryptonix-tests" = pkgs.writeScriptBin "test" "echo bad bad; exit 1";
    }
  );
}
