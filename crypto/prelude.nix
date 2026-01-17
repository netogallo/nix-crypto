{ pkgs, lib, ... }:
let
  type-checker = { file }:
  {
    function = args: func:
      let
        check = { name, type }: value:
          type.merge [ name ] [ { inherit value file; } ]
        ; 
        check-apply = f: arg: value: f (check arg value);
      in
        lib.foldl check-apply func args
    ;
  };
in
  {
    inherit type-checker;
  }
