# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import autoinstall
from autoinstall_helpers import CHECKSUM, checksum_listing, image_named


###########################################################
# Verifying the download
#
# The image arrives over the network and is then booted on a machine that
# installs itself from it. A truncated or substituted image is only noticed
# once it is already running, so it is checked first.
###########################################################

def test_the_checksums_are_published_beside_the_images():
    assert autoinstall.get_checksum_listing_url("24.04") == \
        "https://releases.ubuntu.com/24.04/SHA256SUMS"


def test_a_published_checksum_is_read():
    listing = checksum_listing((CHECKSUM, image_named("24.04.1")))

    assert autoinstall.parse_checksum_listing(listing) == {
        image_named("24.04.1"): CHECKSUM}


def test_a_checksum_is_matched_to_its_own_image():
    # The listing covers every image published for the release.
    listing = checksum_listing(
        ("0" * 64, "ubuntu-24.04.1-desktop-amd64.iso"),
        (CHECKSUM, image_named("24.04.1")))

    checksums = autoinstall.parse_checksum_listing(listing)

    assert checksums[image_named("24.04.1")] == CHECKSUM


@pytest.mark.parametrize("listing", [
    "",
    None,
    "not a checksum listing",
    "tooshort *ubuntu-24.04.1-live-server-amd64.iso",
])
def test_an_unusable_checksum_listing_reads_as_nothing(listing):
    assert autoinstall.parse_checksum_listing(listing) == {}



def test_a_matching_image_verifies(published_checksum, monkeypatch, tmp_path):
    target = tmp_path / "ubuntu.iso"
    target.write_bytes(b"data")
    monkeypatch.setattr(
        autoinstall.hashing, "calculate_file_sha256", lambda **kwargs: CHECKSUM)

    assert autoinstall.verify_image_checksum(
        str(target), "24.04", image_named("24.04.1")) is True


def test_a_checksum_comparison_ignores_case(published_checksum, monkeypatch, tmp_path):
    target = tmp_path / "ubuntu.iso"
    target.write_bytes(b"data")
    monkeypatch.setattr(
        autoinstall.hashing, "calculate_file_sha256", lambda **kwargs: CHECKSUM.upper())

    assert autoinstall.verify_image_checksum(
        str(target), "24.04", image_named("24.04.1")) is True


def test_an_image_that_does_not_match_is_refused(published_checksum, monkeypatch, tmp_path):
    target = tmp_path / "ubuntu.iso"
    target.write_bytes(b"data")
    monkeypatch.setattr(
        autoinstall.hashing, "calculate_file_sha256", lambda **kwargs: "0" * 64)

    assert autoinstall.verify_image_checksum(
        str(target), "24.04", image_named("24.04.1")) is False


def test_an_image_with_no_published_checksum_is_refused(published_checksum, tmp_path):
    # Nothing to compare against is not the same as a match.
    published_checksum["checksums"] = {"something-else.iso": CHECKSUM}
    target = tmp_path / "ubuntu.iso"
    target.write_bytes(b"data")

    assert autoinstall.verify_image_checksum(
        str(target), "24.04", image_named("24.04.1")) is False


def test_an_unreadable_image_is_refused(published_checksum, monkeypatch, tmp_path):
    target = tmp_path / "ubuntu.iso"
    target.write_bytes(b"data")
    monkeypatch.setattr(
        autoinstall.hashing, "calculate_file_sha256", lambda **kwargs: None)

    assert autoinstall.verify_image_checksum(
        str(target), "24.04", image_named("24.04.1")) is False


def test_the_checksums_are_fetched_into_a_directory_that_is_removed(monkeypatch, tmp_path):
    seen = {}

    def fetch_release_checksums(work_dir, **kwargs):
        seen["work_dir"] = work_dir
        return {image_named("24.04.1"): CHECKSUM}

    monkeypatch.setattr(autoinstall, "fetch_release_checksums", fetch_release_checksums)
    monkeypatch.setattr(
        autoinstall.hashing, "calculate_file_sha256", lambda **kwargs: CHECKSUM)

    assert autoinstall.verify_image_checksum(
        str(tmp_path / "ubuntu.iso"), "24.04", image_named("24.04.1")) is True
    assert seen["work_dir"]
    assert not os.path.exists(seen["work_dir"])


def test_the_work_directory_is_removed_when_fetching_fails(monkeypatch, tmp_path):
    seen = {}

    def fetch_release_checksums(work_dir, **kwargs):
        seen["work_dir"] = work_dir
        raise RuntimeError("network")

    monkeypatch.setattr(autoinstall, "fetch_release_checksums", fetch_release_checksums)

    with pytest.raises(RuntimeError):
        autoinstall.verify_image_checksum(
            str(tmp_path / "ubuntu.iso"), "24.04", image_named("24.04.1"))
    assert not os.path.exists(seen["work_dir"])


def test_an_image_is_refused_without_a_work_directory(published_checksum, monkeypatch, tmp_path):
    monkeypatch.setattr(
        autoinstall.fileops, "create_temporary_directory", lambda **kwargs: (False, ""))

    assert autoinstall.verify_image_checksum(
        str(tmp_path / "ubuntu.iso"), "24.04", image_named("24.04.1")) is False


def test_a_pretend_run_verifies_without_fetching_anything(monkeypatch, tmp_path):
    # A pretend run downloads nothing, so there is no listing to check.
    def fail(**kwargs):
        raise AssertionError("nothing should be fetched in a pretend run")

    monkeypatch.setattr(autoinstall, "fetch_release_checksums", fail)
    monkeypatch.setattr(autoinstall.hashing, "calculate_file_sha256", fail)

    assert autoinstall.verify_image_checksum(
        str(tmp_path / "ubuntu.iso"), "24.04", image_named("24.04.1"),
        pretend_run = True) is True
