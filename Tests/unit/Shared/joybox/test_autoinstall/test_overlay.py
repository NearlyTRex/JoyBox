# Third-party imports
import pytest
import yaml

# Local imports
from joybox import autoinstall
from autoinstall_helpers import complete_profile


###########################################################
# Merging an overlay
###########################################################

def test_no_overlay_leaves_the_document_as_it_is():
    base = {"autoinstall": {"version": 1}}

    assert autoinstall.merge_autoinstall_data(base, None) is base


def test_an_overlay_onto_nothing_is_taken_whole():
    overlay = {"autoinstall": {"snaps": [{"name": "lxd"}]}}

    merged = autoinstall.merge_autoinstall_data(None, overlay)

    assert merged == overlay
    assert merged is not overlay


def test_dictionaries_merge_key_by_key():
    base = {"autoinstall": {"ssh": {"install-server": True}, "version": 1}}
    overlay = {"autoinstall": {"ssh": {"allow-pw": False}}}

    merged = autoinstall.merge_autoinstall_data(base, overlay)

    assert merged["autoinstall"]["ssh"] == {"install-server": True, "allow-pw": False}
    assert merged["autoinstall"]["version"] == 1


def test_known_lists_are_added_to_without_repeats():
    base = {"packages": ["curl", "git"]}
    overlay = {"packages": ["git", "nvtop"]}

    assert autoinstall.merge_autoinstall_data(base, overlay)["packages"] == ["curl", "git", "nvtop"]


def test_other_lists_are_replaced():
    base = {"groups": ["sudo"]}

    assert autoinstall.merge_autoinstall_data(base, {"groups": ["video"]})["groups"] == ["video"]


def test_plain_values_are_overridden():
    base = {"timezone": "Etc/UTC"}

    assert autoinstall.merge_autoinstall_data(base, {"timezone": "Europe/London"}) == {
        "timezone": "Europe/London"}


def test_the_base_document_is_not_changed():
    base = {"packages": ["curl"], "ssh": {"install-server": True}}

    autoinstall.merge_autoinstall_data(base, {"packages": ["git"], "ssh": {"allow-pw": True}})

    assert base == {"packages": ["curl"], "ssh": {"install-server": True}}


def test_an_overlay_keeps_the_generated_account():
    overlay = {"autoinstall": {"user-data": {"runcmd": ["nvidia-smi"]}}}

    data = yaml.safe_load(autoinstall.build_user_data(complete_profile(), overlay))
    user_data = data["autoinstall"]["user-data"]

    assert user_data["runcmd"] == ["nvidia-smi"]
    assert user_data["users"][1]["name"] == "homelab"


###########################################################
# Reading an overlay
###########################################################

def write_overlay(tmp_path, contents, name = "overlay.yaml"):
    overlay_file = tmp_path / name
    overlay_file.write_text(contents)
    return str(overlay_file)


def test_a_whole_document_is_read_as_it_is(tmp_path):
    overlay_file = write_overlay(tmp_path, "autoinstall:\n  snaps:\n    - name: lxd\n")

    assert autoinstall.read_overlay_file(overlay_file) == {
        "autoinstall": {"snaps": [{"name": "lxd"}]}}


def test_just_the_contents_are_wrapped(tmp_path):
    overlay_file = write_overlay(tmp_path, "packages:\n  - nvtop\n")

    assert autoinstall.read_overlay_file(overlay_file) == {"autoinstall": {"packages": ["nvtop"]}}


def test_a_missing_overlay_is_refused(tmp_path):
    assert autoinstall.read_overlay_file(str(tmp_path / "absent.yaml")) is None


@pytest.mark.parametrize("contents", [
    "",
    "- just\n- a list\n",
    "{}\n",
    "autoinstall:\n",
    "autoinstall: nothing\n",
    "autoinstall: {}\n",
])
def test_an_overlay_with_nothing_to_merge_is_refused(tmp_path, contents):
    # An empty autoinstall key would replace the whole generated document.
    assert autoinstall.read_overlay_file(write_overlay(tmp_path, contents)) is None


###########################################################
# Writing the seed
###########################################################

def test_the_seed_is_written_in_its_own_directory(tmp_path):
    iso_dir = tmp_path / "iso"

    assert autoinstall.write_seed_files(
        str(iso_dir), complete_profile(),
        overlay = {"autoinstall": {"packages": ["nvtop"]}}) is True

    user_data = (iso_dir / "nocloud" / "user-data").read_text()
    meta_data = (iso_dir / "nocloud" / "meta-data").read_text()
    assert user_data.startswith("#cloud-config\n")
    assert yaml.safe_load(user_data)["autoinstall"]["packages"] == ["nvtop"]
    assert "local-hostname: testbox" in meta_data


def test_supplied_user_data_is_written_as_it_is(tmp_path):
    iso_dir = tmp_path / "iso"

    assert autoinstall.write_seed_files(
        str(iso_dir), complete_profile(), user_data = "#cloud-config\nmine: true\n") is True

    assert (iso_dir / "nocloud" / "user-data").read_text() == "#cloud-config\nmine: true\n"


def test_a_seed_directory_that_cannot_be_made_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(autoinstall.fileops, "make_directory", lambda **kwargs: False)

    assert autoinstall.write_seed_files(str(tmp_path / "iso"), complete_profile()) is False


def test_a_seed_file_that_cannot_be_written_fails(tmp_path, monkeypatch):
    written = []

    def write_text_file(src, **kwargs):
        written.append(src)
        return False

    monkeypatch.setattr(autoinstall.serialization, "write_text_file", write_text_file)

    assert autoinstall.write_seed_files(str(tmp_path / "iso"), complete_profile()) is False
    assert len(written) == 1
