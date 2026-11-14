# Imports
import os
import shutil

# Third-party imports
import pytest

# Local imports
from joybox import ubunturelease

pytestmark = [pytest.mark.integration, pytest.mark.slow]


###########################################################
# Checking Ubuntu's own signature
#
# The checksums are only worth as much as the connection that fetched them
# unless the signature over them is checked. These run the real gpg against
# a real listing and the key a distribution ships, rather than a stand-in for
# either, because the point is that the two actually agree.
###########################################################

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "ubunturelease_files")


def signed_releases():
    # Every release kept beside the test, as <release>.SHA256SUMS and the
    # detached signature over it. Signing a listing here would need Ubuntu's
    # private key, so real ones are kept instead.
    if not os.path.isdir(FIXTURE_DIR):
        return []
    names = [name for name in os.listdir(FIXTURE_DIR) if name.endswith(".SHA256SUMS")]
    releases = [name[: -len(".SHA256SUMS")] for name in names]
    return sorted(
        release for release in releases
        if os.path.isfile(os.path.join(FIXTURE_DIR, release + ".SHA256SUMS.gpg")))


@pytest.fixture
def ubuntu_keyring():
    keyring = "/usr/share/keyrings/ubuntu-archive-keyring.gpg"
    if not os.path.isfile(keyring):
        pytest.skip("no ubuntu keyring on this machine")
    return keyring


def copy_signed_release(release, tmp_path):
    listing = tmp_path / "SHA256SUMS"
    signature = tmp_path / "SHA256SUMS.gpg"
    shutil.copy(os.path.join(FIXTURE_DIR, release + ".SHA256SUMS"), str(listing))
    shutil.copy(os.path.join(FIXTURE_DIR, release + ".SHA256SUMS.gpg"), str(signature))
    return str(listing), str(signature)


@pytest.fixture
def signed_files(tmp_path, ubuntu_keyring):
    releases = signed_releases()
    if not releases:
        pytest.skip("no signed listing kept for this test")
    return copy_signed_release(releases[0], tmp_path)


def test_at_least_one_signed_listing_is_kept():
    # These tests skip without a fixture, so losing the fixtures would leave
    # the signature check with no evidence it works and nothing failing.
    assert signed_releases()


@pytest.mark.parametrize("release", signed_releases())
@pytest.mark.requires_binary("gpg")
def test_a_real_signature_is_accepted(release, tmp_path, ubuntu_keyring):
    # The shipped fingerprint is what a build trusts by default, so what has
    # to hold is that it accepts the releases people build from, not that it
    # accepts the one release this test was written against.
    listing, signature = copy_signed_release(release, tmp_path)

    assert ubunturelease.verify_checksum_signature(
        listing_file = listing,
        signature_file = signature,
        keyring_file = ubuntu_keyring,
        fingerprint = ubunturelease.default_signing_fingerprint) is True


@pytest.mark.parametrize("release", signed_releases())
@pytest.mark.requires_binary("gpg")
def test_a_listing_changed_after_signing_is_refused(release, tmp_path, ubuntu_keyring):
    # This is the case the signature exists for: a checksum swapped for one
    # matching a substituted image.
    listing, signature = copy_signed_release(release, tmp_path)
    tampered = tmp_path / "tampered"
    with open(listing, "r", encoding = "utf-8") as handle:
        contents = handle.read()
    tampered.write_text("0" + contents[1:])

    assert ubunturelease.verify_checksum_signature(
        listing_file = str(tampered),
        signature_file = signature,
        keyring_file = ubuntu_keyring,
        fingerprint = ubunturelease.default_signing_fingerprint) is False


@pytest.mark.requires_binary("gpg")
def test_a_signature_from_another_key_is_refused(signed_files, ubuntu_keyring):
    # The keyring holds every key the distribution trusts; only one signs
    # these images.
    listing, signature = signed_files

    assert ubunturelease.verify_checksum_signature(
        listing_file = listing,
        signature_file = signature,
        keyring_file = ubuntu_keyring,
        fingerprint = "0" * 40) is False


@pytest.mark.requires_binary("gpg")
def test_an_empty_signature_is_refused(signed_files, ubuntu_keyring, tmp_path):
    listing, _ = signed_files
    empty = tmp_path / "empty.gpg"
    empty.write_bytes(b"")

    assert ubunturelease.verify_checksum_signature(
        listing_file = listing,
        signature_file = str(empty),
        keyring_file = ubuntu_keyring,
        fingerprint = ubunturelease.default_signing_fingerprint) is False
