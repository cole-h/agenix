{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.age;
  rage = pkgs.callPackage ../pkgs/rage.nix {};
  ageBin = "${rage}/bin/rage";

  users = config.users.users;

  identities = builtins.concatStringsSep " " (map (path: "-i ${path}") cfg.sshKeyPaths);
  installSecret = secretType: ''
    echo "decrypting '${secretType.file}' to '${cfg.secretsMountPoint}/$_count/${secretType.name}'..."
    TMP_FILE="${cfg.secretsMountPoint}/$_count/${secretType.name}.tmp"
    mkdir -p "$(dirname "${cfg.secretsMountPoint}/$_count/${secretType.name}")"
    mkdir -p "$(dirname "${secretType.path}")"
    (umask 0400; LANG=${config.i18n.defaultLocale} ${ageBin} --decrypt ${identities} -o "$TMP_FILE" "${secretType.file}")
    chmod ${secretType.mode} "$TMP_FILE"
    chown ${secretType.owner}:${secretType.group} "$TMP_FILE"
    mv -f "$TMP_FILE" "${cfg.secretsMountPoint}/$_count/${secretType.name}"
    [ "${secretType.path}" != "/run/secrets/${secretType.name}" ] && ln -sfn "/run/secrets/${secretType.name}" "${secretType.path}"
  '';

  rootOwnedSecrets = builtins.filter (st: st.owner == "root" && st.group == "root") (builtins.attrValues cfg.secrets);
  installRootOwnedSecrets = builtins.concatStringsSep "\n" (["echo '[agenix] decrypting root secrets...'"] ++ (map installSecret rootOwnedSecrets));

  nonRootSecrets = builtins.filter (st: st.owner != "root" || st.group != "root") (builtins.attrValues cfg.secrets);
  installNonRootSecrets = builtins.concatStringsSep "\n" (["echo '[agenix] decrypting non-root secrets...'"] ++ (map installSecret nonRootSecrets));

  secretType = types.submodule ({ config, ... }: {
    options = {
      name = mkOption {
        type = types.str;
        default = config._module.args.name;
        description = ''
          Name of the file used in /run/secrets
        '';
      };
      file = mkOption {
        type = types.path;
        description = ''
          Age file the secret is loaded from.
        '';
      };
      path = mkOption {
          type = types.str;
          default = "/run/secrets/${config.name}";
          description = ''
            Path where the decrypted secret is installed.
          '';
        };
      mode = mkOption {
        type = types.str;
        default = "0400";
        description = ''
          Permissions mode of the in octal.
        '';
      };
      owner = mkOption {
        type = types.str;
        default = "root";
        description = ''
          User of the file.
        '';
      };
      group = mkOption {
        type = types.str;
        default = users.${config.owner}.group;
        description = ''
          Group of the file.
        '';
      };
    };
  });
in {
  options.age = {
    secrets = mkOption {
      type = types.attrsOf secretType;
      default = {};
      description = ''
        Attrset of secrets.
      '';
    };
    secretsMountPoint = mkOption {
      type = types.addCheck types.str
        (s:
          (builtins.match "[ \t\n]*" s) == null # non-empty
            && (builtins.match ".+/" s) == null) # without trailing slash
      // { description = "${types.str.description} (with check: non-empty without trailing slash)"; };
      default = "/run/secrets.d";
      description = ''
        Where secrets are created before they are symlinked to /run/secrets
      '';
    };
    sshKeyPaths = mkOption {
      type = types.listOf types.path;
      default = if config.services.openssh.enable then
                  map (e: e.path) (lib.filter (e: e.type == "rsa" || e.type == "ed25519") config.services.openssh.hostKeys)
                else [];
      description = ''
        Path to SSH keys to be used as identities in age decryption.
      '';
    };
  };
  config = mkIf (cfg.secrets != {}) {
    assertions = [{
      assertion = cfg.sshKeyPaths != [];
      message = "age.sshKeyPaths must be set.";
    }];

    # Create a new directory full of secrets for symlinking (this helps
    # ensure removed secrets are actually removed, or at least become
    # invalid symlinks).
    system.activationScripts.agenixMountSecrets = ''
      _count="$(basename "$(readlink /run/secrets)" || echo 0)"
      (( ++_count ))
      echo "[agenix] symlinking new secrets generation $_count to /run/secrets..."
      mkdir -pm 0750 "${cfg.secretsMountPoint}"
      mount | grep "${cfg.secretsMountPoint} type ramfs" -q || mount -t ramfs none "${cfg.secretsMountPoint}" -o nodev,nosuid,mode=0750
      mkdir -pm 0750 "${cfg.secretsMountPoint}/$_count"
      chown :keys "${cfg.secretsMountPoint}" "${cfg.secretsMountPoint}/$_count"
      ln -sfn "${cfg.secretsMountPoint}/$_count" /run/secrets
    '';

    # Secrets with root owner and group can be installed before users
    # exist. This allows user password files to be encrypted.
    system.activationScripts.agenixRoot = {
      text = installRootOwnedSecrets;
      deps = [ "agenixMountSecrets" ];
    };
    system.activationScripts.users.deps = [ "agenixRoot" ];

    # Other secrets need to wait for users and groups to exist.
    system.activationScripts.agenix = stringAfter [ "users" "groups" ] installNonRootSecrets;
  };
}
