# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import autoinstall
from autoinstall_helpers import complete_profile, image_named


###########################################################
# Getting the stock image
###########################################################

@pytest.fixture
def release(monkeypatch):
    state = {
        "image": image_named("24.04.1"),
        "download_ok": True,
        "verified": True,
        "downloaded": [],
        "verified_files": [],
    }

    def download_url(url, output_file, **kwargs):
        state["downloaded"].append(url)
        if state["download_ok"]:
            with open(output_file, "w") as handle:
                handle.write("image")
        return state["download_ok"]

    def verify_image_checksum(iso_file, image, verify_signature, **kwargs):
        state["verified_files"].append((iso_file, image, verify_signature))
        return state["verified"]

    monkeypatch.setattr(
        autoinstall, "find_latest_release_image", lambda **kwargs: state["image"])
    monkeypatch.setattr(autoinstall.network, "download_url", download_url)
    monkeypatch.setattr(autoinstall, "verify_image_checksum", verify_image_checksum)
    return state


def obtain(tmp_path, **kwargs):
    defaults = dict(output_file = str(tmp_path / "stock.iso"), version = "24.04")
    defaults.update(kwargs)
    return autoinstall.obtain_source_image(**defaults)


def test_a_supplied_image_is_used_without_a_download(release, tmp_path):
    supplied = tmp_path / "mine.iso"
    supplied.write_text("mine")

    assert obtain(tmp_path, source_file = str(supplied)) == str(supplied)
    assert release["downloaded"] == []
    assert release["verified_files"] == []


def test_a_supplied_image_that_is_missing_is_not_replaced_by_a_download(release, tmp_path):
    # A mistyped path would otherwise fetch a three gigabyte image instead.
    assert obtain(tmp_path, source_file = str(tmp_path / "absent.iso")) is None
    assert release["downloaded"] == []


def test_the_newest_image_is_downloaded_and_verified(release, tmp_path):
    output_file = str(tmp_path / "stock.iso")

    assert obtain(tmp_path, verify_signature = False) == output_file
    assert release["downloaded"] == [
        "https://releases.ubuntu.com/24.04/" + image_named("24.04.1")]
    assert release["verified_files"] == [(output_file, image_named("24.04.1"), False)]


def test_a_download_is_not_verified_when_asked_not_to(release, tmp_path):
    assert obtain(tmp_path, verify = False) == str(tmp_path / "stock.iso")
    assert release["verified_files"] == []


def test_a_download_that_does_not_verify_is_removed(release, tmp_path):
    release["verified"] = False

    assert obtain(tmp_path) is None
    assert not (tmp_path / "stock.iso").exists()


def test_a_failed_download_is_reported(release, tmp_path):
    release["download_ok"] = False

    assert obtain(tmp_path) is None
    assert release["verified_files"] == []


def test_nothing_is_downloaded_when_no_image_is_published(release, tmp_path):
    release["image"] = None

    assert obtain(tmp_path) is None
    assert release["downloaded"] == []


def test_an_earlier_download_is_reused_once_it_verifies(release, tmp_path):
    (tmp_path / "stock.iso").write_text("earlier")

    assert obtain(tmp_path) == str(tmp_path / "stock.iso")
    assert release["downloaded"] == []
    assert len(release["verified_files"]) == 1


def test_an_earlier_download_is_reused_unchecked_when_asked(release, tmp_path):
    (tmp_path / "stock.iso").write_text("earlier")

    assert obtain(tmp_path, verify = False) == str(tmp_path / "stock.iso")
    assert release["downloaded"] == []


def test_an_earlier_download_that_does_not_verify_is_fetched_again(release, monkeypatch, tmp_path):
    (tmp_path / "stock.iso").write_text("truncated")
    results = iter([False, True])
    monkeypatch.setattr(autoinstall, "verify_image_checksum", lambda **kwargs: next(results))

    assert obtain(tmp_path) == str(tmp_path / "stock.iso")
    assert (tmp_path / "stock.iso").read_text() == "image"
    assert len(release["downloaded"]) == 1


def test_an_earlier_download_is_discarded_when_nothing_is_published(release, tmp_path):
    (tmp_path / "stock.iso").write_text("earlier")
    release["image"] = None

    assert obtain(tmp_path) is None
    assert not (tmp_path / "stock.iso").exists()
    assert release["verified_files"] == []


###########################################################
# Building the image
###########################################################

GRUB_CONFIG = "set timeout=30\nmenuentry \"Install\" {\n\tlinux\t/casper/vmlinuz quiet ---\n}\n"


@pytest.fixture
def stock(monkeypatch, tmp_path):
    source_file = tmp_path / "stock.iso"
    source_file.write_text("stock")
    state = {
        "source_file": str(source_file),
        "work_dir": tmp_path / "work",
        "work_dir_ok": True,
        "tree_ok": True,
        "boot_images_ok": True,
        "create_ok": True,
        "created": [],
        "obtained": [],
    }

    def create_temporary_directory(**kwargs):
        state["work_dir"].mkdir()
        return (state["work_dir_ok"], str(state["work_dir"]))

    def extract_buildable_iso_tree(iso_file, extract_dir, **kwargs):
        grub_dir = os.path.join(extract_dir, "boot", "grub")
        os.makedirs(grub_dir)
        with open(os.path.join(grub_dir, "grub.cfg"), "w") as handle:
            handle.write(GRUB_CONFIG)
        return state["tree_ok"]

    def create_bootable_iso(iso_file, source_dir, **kwargs):
        with open(os.path.join(source_dir, "nocloud", "user-data")) as handle:
            user_data = handle.read()
        with open(os.path.join(source_dir, "boot", "grub", "grub.cfg")) as handle:
            grub = handle.read()
        state["created"].append(dict(kwargs, iso_file = iso_file, user_data = user_data, grub = grub))
        return state["create_ok"]

    real_obtain = autoinstall.obtain_source_image

    def obtain_source_image(**kwargs):
        state["obtained"].append(kwargs)
        return real_obtain(**kwargs)

    monkeypatch.setattr(
        autoinstall.fileops, "create_temporary_directory", create_temporary_directory)
    monkeypatch.setattr(autoinstall.iso, "extract_buildable_iso_tree", extract_buildable_iso_tree)
    monkeypatch.setattr(
        autoinstall.iso, "extract_iso_boot_images", lambda **kwargs: state["boot_images_ok"])
    monkeypatch.setattr(autoinstall.iso, "create_bootable_iso", create_bootable_iso)
    monkeypatch.setattr(autoinstall, "obtain_source_image", obtain_source_image)
    return state


def build(stock, tmp_path, **kwargs):
    defaults = dict(
        output_file = str(tmp_path / "out" / "autoinstall.iso"),
        source_file = stock["source_file"],
        profile = complete_profile())
    defaults.update(kwargs)
    return autoinstall.build_autoinstall_image(**defaults)


def test_an_image_is_built_from_the_stock_one(stock, tmp_path):
    assert build(stock, tmp_path) is True

    created = stock["created"][0]
    work_dir = str(stock["work_dir"])
    assert created["iso_file"] == str(tmp_path / "out" / "autoinstall.iso")
    assert created["volume_name"] == "Ubuntu-Server 24.04"
    assert created["bios_boot_image"] == autoinstall.bios_boot_image
    assert created["efi_boot_image"] == os.path.join(work_dir, "efi.img")
    assert created["mbr_image"] == os.path.join(work_dir, "mbr.img")
    assert created["user_data"].startswith("#cloud-config\n")
    assert "autoinstall ds=nocloud" in created["grub"]
    assert (tmp_path / "out").is_dir()
    assert not stock["work_dir"].exists()


def test_the_stock_image_is_kept_beside_the_output(stock, tmp_path):
    build(stock, tmp_path)

    assert stock["obtained"][0]["output_file"] == str(tmp_path / "out" / "ubuntu-server-24.04.iso")


def test_the_stock_image_can_be_kept_elsewhere(stock, tmp_path):
    build(stock, tmp_path, download_file = str(tmp_path / "cache.iso"))

    assert stock["obtained"][0]["output_file"] == str(tmp_path / "cache.iso")


def test_an_incomplete_profile_is_refused_before_anything_is_fetched(stock, tmp_path):
    assert build(stock, tmp_path, profile = complete_profile(username = "")) is False
    assert stock["obtained"] == []


def test_the_configured_profile_is_used_when_none_is_given(stock, isolated_settings, tmp_path):
    assert build(stock, tmp_path, profile = None) is False
    assert stock["obtained"] == []


def test_a_supplied_seed_needs_no_account(stock, tmp_path):
    user_data_file = tmp_path / "user-data"
    user_data_file.write_text("#cloud-config\nmine: true\n")

    assert build(
        stock, tmp_path,
        profile = complete_profile(username = ""),
        user_data_file = str(user_data_file)) is True
    assert stock["created"][0]["user_data"] == "#cloud-config\nmine: true\n"


def test_a_missing_seed_is_refused(stock, tmp_path):
    assert build(stock, tmp_path, user_data_file = str(tmp_path / "absent")) is False
    assert stock["obtained"] == []


def test_an_empty_seed_is_refused(stock, tmp_path):
    user_data_file = tmp_path / "user-data"
    user_data_file.write_text("")

    assert build(stock, tmp_path, user_data_file = str(user_data_file)) is False
    assert stock["obtained"] == []


def test_an_overlay_is_merged_into_the_seed(stock, tmp_path):
    overlay_file = tmp_path / "overlay.yaml"
    overlay_file.write_text("packages:\n  - nvtop\n")

    assert build(stock, tmp_path, overlay_file = str(overlay_file)) is True
    assert "nvtop" in stock["created"][0]["user_data"]


def test_the_profile_overlay_is_used_when_none_is_given(stock, tmp_path):
    overlay_file = tmp_path / "overlay.yaml"
    overlay_file.write_text("snaps:\n  - name: lxd\n")

    assert build(stock, tmp_path, profile = complete_profile(overlay_file = str(overlay_file))) is True
    assert "lxd" in stock["created"][0]["user_data"]


def test_an_unreadable_overlay_is_refused(stock, tmp_path):
    assert build(stock, tmp_path, overlay_file = str(tmp_path / "absent.yaml")) is False
    assert stock["obtained"] == []


def test_an_output_directory_that_cannot_be_made_is_refused(stock, monkeypatch, tmp_path):
    monkeypatch.setattr(autoinstall.fileops, "make_directory", lambda **kwargs: False)

    assert build(stock, tmp_path) is False
    assert stock["obtained"] == []


def test_no_stock_image_means_no_build(stock, tmp_path):
    assert build(stock, tmp_path, source_file = str(tmp_path / "absent.iso")) is False
    assert stock["created"] == []


def test_no_work_directory_means_no_build(stock, tmp_path):
    stock["work_dir_ok"] = False

    assert build(stock, tmp_path) is False
    assert stock["created"] == []


@pytest.mark.parametrize("failing", ["tree_ok", "boot_images_ok", "create_ok"])
def test_a_failed_image_step_fails_the_build(stock, tmp_path, failing):
    stock[failing] = False

    assert build(stock, tmp_path) is False
    assert not stock["work_dir"].exists()


def test_a_seed_that_cannot_be_written_fails_the_build(stock, monkeypatch, tmp_path):
    monkeypatch.setattr(autoinstall, "write_seed_files", lambda **kwargs: False)

    assert build(stock, tmp_path) is False
    assert stock["created"] == []
    assert not stock["work_dir"].exists()


def test_a_bootloader_that_cannot_be_patched_fails_the_build(stock, monkeypatch, tmp_path):
    monkeypatch.setattr(autoinstall, "patch_boot_configs", lambda **kwargs: False)

    assert build(stock, tmp_path) is False
    assert stock["created"] == []
    assert not stock["work_dir"].exists()
