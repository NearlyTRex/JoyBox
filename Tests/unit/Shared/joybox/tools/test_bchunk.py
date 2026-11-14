# Local imports
from joybox.tools import bchunk
from tools_helpers import assert_installs_nothing


def test_the_program_is_the_exe_in_the_install_dir(isolated_settings):
    isolated_settings.set_value("Tools.Bchunk", "bchunk_exe", "bchunk")
    isolated_settings.set_value("Tools.Bchunk", "bchunk_install_dir", "/opt/bchunk/bin")

    tool = bchunk.Bchunk()

    assert tool.get_name() == "Bchunk"
    assert tool.get_config() == {"Bchunk": {"program": "/opt/bchunk/bin/bchunk"}}


def test_variables_in_the_install_dir_are_expanded(isolated_settings, monkeypatch):
    monkeypatch.setenv("JOYBOX_TEST_ROOT", "/srv/tools")
    isolated_settings.set_value("Tools.Bchunk", "bchunk_exe", "bchunk")
    isolated_settings.set_value("Tools.Bchunk", "bchunk_install_dir", "$JOYBOX_TEST_ROOT/bchunk")

    assert bchunk.Bchunk().get_config()["Bchunk"]["program"] == "/srv/tools/bchunk/bchunk"


def test_setup_installs_nothing(steps):
    assert_installs_nothing(steps, bchunk.Bchunk())
