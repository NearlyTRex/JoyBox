# Local imports
from joybox import autoinstall

CHECKSUM = "9bc6028870aef3f74f4e16b900008179e78b130e6b0b9a522657b6d34a0c4e6c"
UBUNTU_FINGERPRINT = "843938DF228D22F7B3742BC0D94AA3F0EFE21092"
PASSWORD_HASH = "$6$rounds=656000$abc$def"


def listing_with(*images):
    return "".join('<a href="%s">%s</a>\n' % (image, image) for image in images)


def image_named(version):
    return "ubuntu-%s-live-server-amd64.iso" % version


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


def checksum_listing(*entries):
    return "".join("%s *%s\n" % (checksum, name) for checksum, name in entries)


def status_line(fingerprint = UBUNTU_FINGERPRINT):
    return "[GNUPG:] NEWSIG\n[GNUPG:] VALIDSIG %s 2026-09-15 1789499472 0 4 0 1 10 00 %s\n" % (
        fingerprint, fingerprint)


def check_signature(signature_check, tmp_path, **kwargs):
    listing = tmp_path / "SHA256SUMS"
    listing.write_text("")
    signature = tmp_path / "SHA256SUMS.gpg"
    signature.write_bytes(b"")
    defaults = dict(
        listing_file = str(listing),
        signature_file = str(signature),
        keyring_file = signature_check["keyring"],
        fingerprint = UBUNTU_FINGERPRINT)
    defaults.update(kwargs)
    return autoinstall.verify_checksum_signature(**defaults)
