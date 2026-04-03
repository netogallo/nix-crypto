{ pkgs, lib, ... }:
let
  type-checker = { }:
  {
    function = args: func:
      let
        check = { name, type }: value:
          type.type.merge [ name ] [ { inherit value; inherit (type) file; } ]
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
