# Third-party imports
import pytest

# Local imports
from joybox import autoinstall
from autoinstall_helpers import UBUNTU_FINGERPRINT, check_signature, status_line


###########################################################
# Who signed the checksums
#
# A checksum fetched over the same connection as the image proves only that
# the two agree. The signature over it is what ties the image back to the
# people who published it, so it is checked against a key obtained some other
# way rather than one fetched alongside.
###########################################################

def test_the_signature_is_published_beside_the_checksums():
    assert autoinstall.get_checksum_signature_url("24.04") == \
        "https://releases.ubuntu.com/24.04/SHA256SUMS.gpg"


def test_a_signature_from_the_expected_key_is_accepted(signature_check, tmp_path):
    assert check_signature(signature_check, tmp_path) is True


def test_the_signature_is_checked_against_the_given_keyring(signature_check, tmp_path):
    # Checking against whatever keys happen to be on the machine would accept
    # a signature from any of them.
    check_signature(signature_check, tmp_path)
    command = signature_check["commands"][0]

    assert "--no-default-keyring" in command
    assert signature_check["keyring"] in command


def test_a_signature_that_does_not_check_out_is_refused(signature_check, tmp_path):
    # gpg reports nothing valid when the listing was changed after signing.
    signature_check["status"] = "[GNUPG:] BADSIG 843938DF228D22F7B3742BC0D94AA3F0EFE21092\n"

    assert check_signature(signature_check, tmp_path) is False


def test_a_signature_from_another_key_is_refused(signature_check, tmp_path):
    # The keyring may hold many keys; only one publishes these images.
    signature_check["status"] = status_line("0" * 40)

    assert check_signature(signature_check, tmp_path) is False


def test_a_fingerprint_is_compared_however_it_is_written(signature_check, tmp_path):
    # gpg prints fingerprints in spaced groups.
    spaced = "8439 38DF 228D 22F7 B374  2BC0 D94A A3F0 EFE2 1092"

    assert check_signature(signature_check, tmp_path, fingerprint = spaced) is True


def test_any_trusted_key_is_accepted_when_none_is_named(signature_check, tmp_path):
    signature_check["status"] = status_line("0" * 40)

    assert check_signature(signature_check, tmp_path, fingerprint = "") is True


def test_a_missing_keyring_is_reported(signature_check, tmp_path):
    assert check_signature(
        signature_check, tmp_path, keyring_file = str(tmp_path / "absent.gpg")) is False


def test_a_signature_cannot_be_checked_without_gpg(monkeypatch, tmp_path):
    monkeypatch.setattr(autoinstall.programs, "is_tool_installed", lambda name: False)
    monkeypatch.setattr(autoinstall.programs, "get_tool_program", lambda name: None)
    listing = tmp_path / "SHA256SUMS"
    listing.write_text("")

    assert autoinstall.verify_checksum_signature(str(listing), str(listing)) is False


@pytest.mark.parametrize("status", ["", None, "gpg: no valid OpenPGP data found"])
def test_an_unreadable_verification_is_refused(signature_check, tmp_path, status):
    signature_check["status"] = status

    assert check_signature(signature_check, tmp_path) is False


def test_the_reported_fingerprint_is_read_from_the_status():
    assert autoinstall.get_verified_fingerprint(status_line()) == UBUNTU_FINGERPRINT


def test_byte_status_output_is_decoded():
    assert autoinstall.get_verified_fingerprint(status_line().encode()) == UBUNTU_FINGERPRINT


def test_the_signing_key_is_configurable(isolated_settings, tmp_path):
    # A release signed by a different key, or a machine that keeps its
    # keyrings somewhere else.
    isolated_settings.set_value(
        "UserData.Autoinstall", "autoinstall_signing_fingerprint", "0" * 40)
    isolated_settings.set_value(
        "UserData.Autoinstall", "autoinstall_signing_keyring", str(tmp_path / "other.gpg"))

    assert autoinstall.get_signing_fingerprint() == "0" * 40
    assert autoinstall.get_signing_keyring() == str(tmp_path / "other.gpg")


def test_the_ubuntu_signing_key_is_expected_by_default(isolated_settings):
    assert autoinstall.get_signing_fingerprint() == UBUNTU_FINGERPRINT


def test_the_configured_key_is_used_when_none_is_given(signature_check, isolated_settings, tmp_path):
    isolated_settings.set_value(
        "UserData.Autoinstall", "autoinstall_signing_keyring", signature_check["keyring"])

    assert check_signature(
        signature_check, tmp_path, keyring_file = None, fingerprint = None) is True
    assert signature_check["keyring"] in signature_check["commands"][0]


def test_another_key_is_refused_by_the_configured_fingerprint(signature_check, isolated_settings, tmp_path):
    isolated_settings.set_value(
        "UserData.Autoinstall", "autoinstall_signing_keyring", signature_check["keyring"])
    signature_check["status"] = status_line("0" * 40)

    assert check_signature(
        signature_check, tmp_path, keyring_file = None, fingerprint = None) is False


def test_gpg_is_found_through_the_tool_registry(monkeypatch):
    monkeypatch.setattr(autoinstall.programs, "is_tool_installed", lambda name: name == "Gpg")
    monkeypatch.setattr(autoinstall.programs, "get_tool_program", lambda name: "/tools/" + name)

    assert autoinstall.get_signature_tool() == "/tools/Gpg"
