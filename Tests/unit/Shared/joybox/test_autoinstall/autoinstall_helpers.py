# Local imports
from joybox import autoinstall

PASSWORD_HASH = "$6$rounds=656000$abc$def"


def complete_profile(**overrides):
    profile = {
        "version": "24.04",
        "username": "homelab",
        "hostname": "testbox",
        "password_hash": PASSWORD_HASH,
        "ssh_keys": [],
    }
    profile.update(overrides)
    return profile


def seed_for(**overrides):
    import yaml

    text = autoinstall.build_user_data(complete_profile(**overrides))
    return text, yaml.safe_load(text)
