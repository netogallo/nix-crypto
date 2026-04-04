{ lib }:
let
  inherit (lib) types;

  x509NameType = types.attrsOf types.str;

  basicConstraintsType = types.submodule {
    options = {
      critical = lib.mkOption {
        type = types.bool;
        default = false;
        description = "Whether the BasicConstraints extension is critical.";
      };

      ca = lib.mkOption {
        type = types.bool;
        default = false;
        description = "Whether the certificate is a CA certificate.";
      };
    };
  };

  keyUsageType = types.submodule ({ ... }: {
    options = {
      critical = lib.mkOption {
        type = types.bool;
        default = false;
        description = "Whether the KeyUsage extension is critical.";
      };

      key-cert-sign = lib.mkOption {
        type = types.bool;
        default = false;
        description = "keyCertSign usage bit.";
      };

      crl-sign = lib.mkOption {
        type = types.bool;
        default = false;
        description = "cRLSign usage bit.";
      };
    };
  });

in
  types.submodule ({ ... }: {
    options = {
      subject-public-key = lib.mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Optional subject public key (string).";
      };

      subject-name = lib.mkOption {
        type = x509NameType;
        description = "X509 subject name as an attrset of strings (e.g., CN, O, OU...).";
      };
  
      issuer-name = lib.mkOption {
        type = x509NameType;
        description = "X509 subject name as an attrset of strings (e.g., CN, O, OU...).";
      };
  
      serial = lib.mkOption {
        type = types.int;
        description = "Certificate serial number.";
      };
  
      start-date = lib.mkOption {
        type = types.str; # could be types.strMatching ... if you want to enforce RFC3339
        description = "Start date (string; intended RFC3339).";
      };
  
      expiry-date = lib.mkOption {
        type = types.str; # could be types.strMatching ... if you want to enforce RFC3339
        description = "Expiry date (string; intended RFC3339).";
      };
  
      basic-constraints = lib.mkOption {
        type = types.nullOr basicConstraintsType;
        default = null;
        description = "Optional BasicConstraints extension parameters.";
      };
  
      key-usage = lib.mkOption {
        type = types.nullOr keyUsageType;
        default = null;
        description = "Optional KeyUsage extension parameters.";
      };
    };
  })

