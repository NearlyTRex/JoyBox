# Imports
import base64
import binascii
import json
import os
import re

# Local imports
import joybox.config as config
import joybox.commandbase as commandbase
import joybox.logger as logger
import joybox.serialization as serialization
import joybox.settings as settings

###########################################################
# Remotes from the settings
#
# Each remote locker is an rclone remote whose options come from the
# settings, credentials included, which are usually 1Password references. They
# reach rclone only through the environment of the commands that use the
# remote (RCLONE_CONFIG_<NAME>_<OPTION>), so no credential is written to
# rclone.conf or appears on a command line, where any user can read it.
###########################################################

# Options a remote type always needs
TYPE_OPTIONS = {
    config.RemoteType.SFTP: {

        # SFTP shells have no usable md5sum, so a hash check reports every transfer as corrupted
        "shell_type": "unix",
        "disable_hashcheck": "true",
    },
    config.RemoteType.DRIVE: {
        "scope": "drive",
    },
}

# Options rclone only accepts obscured
OBSCURED_OPTIONS = {"pass", "password", "password2", "key_file_pass"}

# rclone's obscuring key. It is public: obscuring keeps a value from being read
# at a glance, it does not keep it secret
OBSCURE_KEY = bytes([
    0x9c, 0x93, 0x5b, 0x48, 0x73, 0x0a, 0x55, 0x4d, 0x6b, 0xfd, 0x7c, 0x63, 0xc8, 0x86, 0xa9, 0x2b,
    0xd3, 0x90, 0x19, 0x8e, 0xb8, 0x12, 0x8a, 0xfb, 0xf4, 0xde, 0x16, 0x2b, 0x8b, 0x95, 0xf6, 0x38])
OBSCURE_IV_SIZE = 16

# The names rclone can read from the environment
REMOTE_NAME = re.compile(r"^[A-Za-z0-9_]+$")

# What an obscured value is made of: unpadded URL-safe base64
OBSCURED_VALUE = re.compile(r"^[A-Za-z0-9_-]+$")

###########################################################
# Obscuring
###########################################################

# Apply obscure cipher key
def apply_obscure_cipher(data, iv):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    cipher = Cipher(algorithms.AES(OBSCURE_KEY), modes.CTR(iv)).encryptor()
    return cipher.update(data) + cipher.finalize()

# Obscure a value the way `rclone obscure` does
def obscure_value(value, iv = None):
    iv = iv or os.urandom(OBSCURE_IV_SIZE)
    return base64.urlsafe_b64encode(iv + apply_obscure_cipher(value.encode("utf-8"), iv)).decode("ascii").rstrip("=")

# Reveal an obscured value, or None when it is not one
def reveal_value(value):
    if not OBSCURED_VALUE.match(value):
        return None
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except binascii.Error:
        return None
    if len(raw) < OBSCURE_IV_SIZE:
        return None
    try:
        return apply_obscure_cipher(raw[OBSCURE_IV_SIZE:], raw[:OBSCURE_IV_SIZE]).decode("utf-8")
    except UnicodeDecodeError:
        return None

# Obscure a value unless it already is, as `rclone config create` decides
def ensure_obscured(value):
    return value if reveal_value(value) is not None else obscure_value(value)

###########################################################
# Settings
###########################################################

# Get possible remote locker types
def get_remote_locker_types():
    return [
        locker_type for locker_type in config.LockerType.members()
        if locker_type not in (config.LockerType.ALL, config.LockerType.LOCAL, config.LockerType.EXTERNAL)]

# Get locker setting
def get_locker_setting(locker_type, field):
    return settings.get_value("UserData.Share", "locker_%s_%s" % (locker_type.lower(), field), throw_exception = False)

# Get the remote locker whose remote has this name; rclone names are not case sensitive
def find_remote_locker_type(remote_name):
    for locker_type in get_remote_locker_types():
        name = get_locker_setting(locker_type, "name")
        if name and name.lower() == remote_name.lower():
            return locker_type
    return None

# Format rclone option
def format_option_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value)
    return str(value)

# Get a remote's rclone options from its locker's settings, or None when no
# locker names it. Read only when a command uses the remote, so a credential
# is resolved only when it is needed.
def get_remote_options(remote_name):
    locker_type = find_remote_locker_type(remote_name)
    if not locker_type:
        return None
    remote_type = get_locker_setting(locker_type, "type")
    if not remote_type:
        logger.log_error("Locker %s names remote %s but has no type" % (locker_type, remote_name))
        return None
    options = {"type": config.RemoteType.to_lower_string(remote_type)}
    options.update(TYPE_OPTIONS.get(remote_type, {}))
    remote_config = get_locker_setting(locker_type, "config")
    if remote_config:
        parsed = serialization.parse_json_string(remote_config) if isinstance(remote_config, str) else remote_config
        if not isinstance(parsed, dict):
            logger.log_error("Locker %s config must be a JSON object" % locker_type)
            return None
        options.update({key: format_option_value(value) for key, value in parsed.items()})
    remote_token = get_locker_setting(locker_type, "token")
    if remote_token and "token" not in options:
        options["token"] = remote_token
    for option in OBSCURED_OPTIONS & set(options):
        options[option] = ensure_obscured(options[option])
    return options

# Get the environment that defines these remotes for rclone
def get_remote_environment(remote_names):
    environment = {}
    for remote_name in dict.fromkeys(name for name in remote_names if name):
        options = get_remote_options(remote_name)
        if options is None:
            continue
        if not REMOTE_NAME.match(remote_name):
            logger.log_error("Remote %s can't be defined for rclone; use letters, digits and _ only" % remote_name)
            continue
        for option, value in options.items():
            environment["RCLONE_CONFIG_%s_%s" % (remote_name.upper(), option.upper())] = value
    return environment

# Get the options for an rclone command that uses these remotes, on top of
# the caller's own options, which are left as they were
def get_rclone_options(remote_names, options = None):
    rclone_options = options.copy() if options else commandbase.create_command_options()
    environment = dict(rclone_options.get_env())
    environment.update(get_remote_environment(remote_names))
    rclone_options.set_env(environment)
    return rclone_options
