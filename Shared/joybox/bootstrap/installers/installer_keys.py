# Imports
import os
import socket
import getpass

# Local imports
import joybox.bootstrap.constants as constants
from . import installer
from joybox import runoptions
from joybox import logger
from joybox import settings

# Keys this machine needs
# A "secret" key is the same on every machine, so it is written from the value
# a setting resolves to (a 1Password reference) and never made here: the
# backup key decrypts every backup, so a new one would decrypt none of them. A
# "generated" key belongs to this machine alone and is made when missing.
KEYS = [
    {
        "name": "age-backup",
        "kind": "secret",
        "description": "Backup decryption key, from 1Password",
        "path": ("UserData.Backup", "backup_age_identity"),
        "value": ("UserData.Backup", "backup_age_identity_key"),
        "public": ("UserData.Backup", "backup_age_recipient"),
    },
    {
        "name": "ssh",
        "kind": "generated",
        "description": "The vm machine's SSH key",
        "path": ("UserData.Servers", "server_1_key_filepath"),
    },
]

# Keys
class Keys(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
        ]

    def get_key_path(self, key):
        return settings.get_path_value(*key["path"], default_value = "", throw_exception = False) or ""

    def is_installed(self):
        for key in KEYS:
            path = self.get_key_path(key)
            if path and not self.connection.does_file_or_directory_exist(path):
                return False
        return True

    # Write a shared key from its setting, then check it is the one the
    # matching public key belongs to
    def install_secret_key(self, key, path):
        value = settings.get_value(*key["value"], default_value = "", throw_exception = False) or ""
        if not value:
            logger.log_error("Unable to read [%s] %s; store the key in the JoyBox 1Password item, as field %s/%s" % (
                key["value"][0], key["value"][1], key["value"][0], key["value"][1]))
            return False
        self.connection.make_directory(os.path.dirname(path))
        if not self.write_secret_file(path, value.strip() + "\n"):
            logger.log_error(f"Failed to write {path}")
            return False
        public = settings.get_value(*key["public"], default_value = "", throw_exception = False) or ""
        derived = (self.connection.run_output(["age-keygen", "-y", path]) or "").strip()
        if public and derived and derived != public:
            logger.log_error(f"The key written to {path} does not match [{key['public'][0]}] {key['public'][1]}; removing it")
            self.connection.remove_file_or_directory(path)
            return False
        return True

    # Make a key for this machine; ssh-keygen asks for its passphrase itself
    def install_generated_key(self, path):
        self.connection.make_directory(os.path.dirname(path))
        self.connection.change_permission(os.path.dirname(path), "700")
        comment = "%s@%s" % (getpass.getuser(), socket.gethostname())
        if self.connection.run_interactive(["ssh-keygen", "-t", "ed25519", "-f", path, "-C", comment]) != 0:
            logger.log_error(f"Failed to generate {path}")
            return False
        logger.log_info(
            f"Add {path}.pub to [UserData.Autoinstall] autoinstall_ssh_keys and to each server's "
            "authorized_keys so this machine can log in")
        return True

    def install(self):

        # Start install
        logger.log_info("Installing keys")

        # Write each missing key, leaving existing ones alone
        for key in KEYS:
            path = self.get_key_path(key)
            if not path:
                logger.log_info(f"No path is set for the {key['name']} key, skipping")
                continue
            if self.connection.does_file_or_directory_exist(path):
                logger.log_info(f"{path} already exists, skipping")
                continue
            logger.log_info(f"Installing {path}: {key['description']}")
            if key["kind"] == "secret":
                success = self.install_secret_key(key, path)
            else:
                success = self.install_generated_key(path)
            if not success:
                return False

        # All done
        logger.log_info("Keys installed")
        return True

    # Keys are never removed: losing the backup key loses every backup, and an
    # SSH key may be the only way into a server
    def uninstall(self):
        logger.log_info("Keys are left in place; remove them by hand if you mean to")
        return True
