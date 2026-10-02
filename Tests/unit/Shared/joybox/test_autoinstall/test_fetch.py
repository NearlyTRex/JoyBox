# Third-party imports
import pytest

# Local imports
from joybox import autoinstall
from autoinstall_helpers import CHECKSUM, checksum_listing, image_named


###########################################################
# Fetching the checksums
###########################################################

def test_the_checksums_and_their_signature_are_both_fetched(published_files, tmp_path):
    checksums = autoinstall.fetch_release_checksums("24.04", str(tmp_path))

    assert checksums[image_named("24.04.1")] == CHECKSUM
    assert any(url.endswith("SHA256SUMS") for url in published_files["downloaded"])
    assert any(url.endswith("SHA256SUMS.gpg") for url in published_files["downloaded"])


def test_checksums_that_are_not_correctly_signed_are_not_used(published_files, tmp_path):
    published_files["signature_ok"] = False

    assert autoinstall.fetch_release_checksums("24.04", str(tmp_path)) is None


def test_the_signature_check_can_be_turned_off(published_files, tmp_path):
    checksums = autoinstall.fetch_release_checksums(
        "24.04", str(tmp_path), verify_signature = False)

    assert checksums[image_named("24.04.1")] == CHECKSUM
    assert not any(url.endswith(".gpg") for url in published_files["downloaded"])


def test_checksums_that_cannot_be_fetched_are_nothing(published_files, monkeypatch, tmp_path):
    monkeypatch.setattr(autoinstall.network, "download_url", lambda **kwargs: False)

    assert autoinstall.fetch_release_checksums("24.04", str(tmp_path)) is None


def test_checksums_whose_signature_cannot_be_fetched_are_not_used(published_files, tmp_path):
    published_files["failing"] = ("SHA256SUMS.gpg",)

    assert autoinstall.fetch_release_checksums("24.04", str(tmp_path)) is None


@pytest.fixture
def checksum_page(monkeypatch):
    state = {"html": checksum_listing((CHECKSUM, image_named("24.04.1"))), "urls": []}

    def get_remote_html(url, **kwargs):
        state["urls"].append(url)
        return state["html"]

    monkeypatch.setattr(autoinstall.network, "get_remote_html", get_remote_html)
    return state


def test_the_published_checksums_are_read_from_the_listing(checksum_page):
    assert autoinstall.find_release_checksums("24.04") == {image_named("24.04.1"): CHECKSUM}
    assert checksum_page["urls"] == ["https://releases.ubuntu.com/24.04/SHA256SUMS"]


def test_the_checksum_for_one_image_is_found(checksum_page):
    assert autoinstall.find_image_checksum("24.04", image_named("24.04.1")) == CHECKSUM


def test_an_image_missing_from_the_listing_has_no_checksum(checksum_page):
    assert autoinstall.find_image_checksum("24.04", image_named("24.04.9")) is None


def test_an_unfetchable_listing_has_no_checksums(checksum_page):
    checksum_page["html"] = None

    assert autoinstall.find_release_checksums("24.04") == {}
