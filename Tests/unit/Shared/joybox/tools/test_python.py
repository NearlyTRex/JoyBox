# Local imports
from joybox.tools import python
from tools_helpers import assert_installs_nothing


def set_python(settings, venv_dir):
    settings.set_value("Tools.Python", "python_exe", "python3")
    settings.set_value("Tools.Python", "python_pip_exe", "pip3")
    settings.set_value("Tools.Python", "python_install_dir", "/usr/bin")
    settings.set_value("Tools.Python", "python_venv_dir", venv_dir)


def test_the_venv_programs_sit_in_each_platforms_script_dir(isolated_settings):
    set_python(isolated_settings, "/home/tester/.venv")

    tool = python.Python()

    assert tool.get_name() == "Python"
    assert tool.get_config() == {
        "Python": {"program": "/usr/bin/python3", "venv_dir": "/home/tester/.venv"},
        "PythonVenvPython": {"program": {
            "windows": "/home/tester/.venv/Scripts/python3",
            "linux": "/home/tester/.venv/bin/python3",
        }},
        "PythonVenvPip": {"program": {
            "windows": "/home/tester/.venv/Scripts/pip3",
            "linux": "/home/tester/.venv/bin/pip3",
        }},
    }


def test_variables_in_the_venv_dir_are_expanded(isolated_settings, monkeypatch):
    monkeypatch.setenv("HOME", "/home/tester")
    set_python(isolated_settings, "$HOME/.venv")

    config = python.Python().get_config()

    assert config["Python"]["venv_dir"] == "/home/tester/.venv"
    assert config["PythonVenvPip"]["program"]["linux"] == "/home/tester/.venv/bin/pip3"


def test_setup_installs_nothing(steps):
    assert_installs_nothing(steps, python.Python())
