# Imports
import os
import stat

# Third-party imports
import pytest

# Local imports
from joybox import default_settings


###########################################################
# Default settings
#
# bootstrap.py writes this file when none exists, so whether the write
# succeeded has to be answerable - a silently empty config reads back as
# every setting unset.
###########################################################

def read(path):
    with open(path, "r", encoding = "utf-8") as handle:
        return handle.read()


###########################################################
# Generating the content
###########################################################

def test_every_default_section_is_written(tmp_path):
    path = os.path.join(str(tmp_path), "JoyBox.ini")

    default_settings.create_default_config_file(path)

    contents = read(path)
    for section in default_settings.ini_defaults:
        assert "[%s]" % section in contents


def test_only_the_named_sections_are_written(tmp_path):
    path = os.path.join(str(tmp_path), "JoyBox.ini")

    default_settings.create_default_config_file(path, sections = ["UserData.Servers"])

    contents = read(path)
    assert "[UserData.Servers]" in contents
    assert "[UserData.Dirs]" not in contents


def test_an_empty_default_is_written_as_a_comment(tmp_path):
    # An unset value has to round-trip as unset, not as the empty string
    path = os.path.join(str(tmp_path), "JoyBox.ini")

    default_settings.create_default_config_file(path, sections = ["UserData.Servers"])

    assert "; server_0_host = " in read(path)


###########################################################
# Reporting the outcome
###########################################################

def test_a_written_file_reports_success(tmp_path):
    path = os.path.join(str(tmp_path), "JoyBox.ini")

    assert default_settings.create_default_config_file(path) is True


def test_a_missing_parent_directory_is_created(tmp_path):
    path = os.path.join(str(tmp_path), "nested", "deeper", "JoyBox.ini")

    assert default_settings.create_default_config_file(path) is True
    assert os.path.isfile(path)


def test_a_file_that_cannot_be_written_reports_failure(tmp_path):
    # bootstrap.py quits on this rather than carrying on with no settings
    locked = tmp_path / "locked"
    locked.mkdir()
    os.chmod(str(locked), stat.S_IRUSR | stat.S_IXUSR)
    path = os.path.join(str(locked), "JoyBox.ini")

    try:
        assert default_settings.create_default_config_file(path) is False
    finally:
        os.chmod(str(locked), stat.S_IRWXU)


def test_a_pretend_run_writes_nothing(tmp_path):
    path = os.path.join(str(tmp_path), "JoyBox.ini")

    assert default_settings.create_default_config_file(path, pretend_run = True) is True
    assert not os.path.exists(path)
