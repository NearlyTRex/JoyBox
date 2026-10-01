# Imports

# Third-party imports
import pytest

# Local imports
from joybox import release
from release_helpers import install_stored, write


###########################################################
# Installing from stored archives
###########################################################

def test_the_newest_stored_archive_is_used(stored, tmp_path):
    # The list is sorted by name, so the last entry is the highest version.
    archives = tmp_path / "archives"
    write(archives / "Tool-1.0.zip")
    write(archives / "Tool-2.0.zip")

    assert install_stored(archives) is True
    assert stored[0]["archive_file"].endswith("Tool-2.0.zip")


def test_the_oldest_stored_archive_can_be_asked_for(stored, tmp_path):
    archives = tmp_path / "archives"
    write(archives / "Tool-1.0.zip")
    write(archives / "Tool-2.0.zip")

    install_stored(archives, use_first_found = True)

    assert stored[0]["archive_file"].endswith("Tool-1.0.zip")


def test_a_preferred_archive_is_chosen_by_name(stored, tmp_path):
    # Some tools ship one archive per platform in the same directory.
    archives = tmp_path / "archives"
    write(archives / "Tool-1.0-linux.zip")
    write(archives / "Tool-1.0-windows.zip")

    install_stored(archives, preferred_archive = "linux")

    assert stored[0]["archive_file"].endswith("Tool-1.0-linux.zip")


def test_a_preferred_archive_that_is_not_there_installs_nothing(stored, tmp_path):
    archives = tmp_path / "archives"
    write(archives / "Tool-1.0-windows.zip")

    assert install_stored(archives, preferred_archive = "linux") is False
    assert stored == []


def test_an_empty_archive_directory_installs_nothing(stored, tmp_path):
    archives = tmp_path / "archives"
    archives.mkdir()

    assert install_stored(archives) is False
    assert stored == []


def test_a_missing_archive_directory_installs_nothing(stored, tmp_path):
    assert install_stored(tmp_path / "absent") is False
    assert stored == []


def test_a_missing_archive_can_be_skipped_quietly(stored, tmp_path):
    # The locker holds these archives, and a machine that has not downloaded
    # it yet should still finish setting itself up.
    assert install_stored(tmp_path / "absent", skip_if_missing = True) is True
    assert stored == []


def test_a_directory_holding_no_archives_can_be_skipped_quietly(stored, tmp_path):
    archives = tmp_path / "archives"
    write(archives / "notes.txt")

    assert install_stored(archives, skip_if_missing = True) is True
    assert stored == []


def test_a_real_archive_is_not_skipped(stored, tmp_path):
    archives = tmp_path / "archives"
    write(archives / "Tool-1.0.zip")

    assert install_stored(archives, skip_if_missing = True) is True
    assert len(stored) == 1


@pytest.mark.parametrize("option,value", [
    ("search_file", "tool.sh"),
    ("install_files", ["tool.sh"]),
    ("chmod_files", [{"file": "tool.sh", "perms": 755}]),
    ("rename_files", [{"from": "a", "to": "b", "ratio": 90}]),
    ("installer_type", "inno"),
    ("release_type", "Archive"),
])
def test_every_stored_install_option_is_passed_through(stored, tmp_path, option, value):
    archives = tmp_path / "archives"
    write(archives / "Tool-1.0.zip")

    install_stored(archives, **{option: value})

    assert stored[0][option] == value


def test_no_selection_rule_selects_nothing(stored, tmp_path):
    archives = tmp_path / "archives"
    write(archives / "Tool-1.0.zip")

    assert install_stored(archives, use_first_found = False, use_last_found = False) is False
    assert stored == []


def test_an_empty_preference_falls_back_to_the_newest(stored, tmp_path):
    archives = tmp_path / "archives"
    write(archives / "Tool-1.0.zip")
    write(archives / "Tool-2.0.zip")

    install_stored(archives, preferred_archive = "")

    assert stored[0]["archive_file"].endswith("Tool-2.0.zip")


@pytest.mark.parametrize("flag", ["verbose", "pretend_run", "exit_on_failure"])
def test_run_flags_reach_the_install(stored, tmp_path, flag):
    archives = tmp_path / "archives"
    write(archives / "Tool-1.0.zip")

    install_stored(archives, **{flag: True})

    assert stored[0][flag] is True


def test_the_install_result_is_returned(stored, tmp_path, monkeypatch):
    archives = tmp_path / "archives"
    write(archives / "Tool-1.0.zip")
    monkeypatch.setattr(release, "setup_general_release", lambda **kwargs: False)

    assert install_stored(archives) is False
