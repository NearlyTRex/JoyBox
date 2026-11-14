# Local imports
from joybox.tools import cmake
from tools_helpers import assert_installs_nothing


def test_the_program_is_the_exe_in_the_install_dir(isolated_settings):
    isolated_settings.set_value("Tools.Cmake", "cmake_exe", "cmake")
    isolated_settings.set_value("Tools.Cmake", "cmake_install_dir", "/opt/cmake/bin")

    tool = cmake.Cmake()

    assert tool.get_name() == "Cmake"
    assert tool.get_config() == {"Cmake": {"program": "/opt/cmake/bin/cmake"}}


def test_variables_in_the_install_dir_are_expanded(isolated_settings, monkeypatch):
    monkeypatch.setenv("JOYBOX_TEST_ROOT", "/srv/tools")
    isolated_settings.set_value("Tools.Cmake", "cmake_exe", "cmake")
    isolated_settings.set_value("Tools.Cmake", "cmake_install_dir", "$JOYBOX_TEST_ROOT/cmake")

    assert cmake.Cmake().get_config()["Cmake"]["program"] == "/srv/tools/cmake/cmake"


def test_setup_installs_nothing(steps):
    assert_installs_nothing(steps, cmake.Cmake())
