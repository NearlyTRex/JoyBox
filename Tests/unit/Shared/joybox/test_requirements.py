# Imports
import pytest

# Local imports
from joybox import requirements


###########################################################
# Declared requirements
#
# A downloaded tool's own declaration decides what goes into the venv, so the
# formats the forks use have to be read the way pip would read them.
###########################################################

def test_a_requirements_file_is_passed_to_pip_whole(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests<3.0\nfilelock\n")

    assert requirements.get_declared_requirements(str(tmp_path)) == [
        "-r", str(tmp_path / "requirements.txt")]


def test_pyproject_dependencies_are_read(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "gogdl"\ndependencies = ["setuptools", "requests"]\n')

    assert requirements.get_declared_requirements(str(tmp_path)) == ["setuptools", "requests"]


def test_setup_cfg_install_requires_are_read(tmp_path):
    (tmp_path / "setup.cfg").write_text(
        "[options]\ninstall_requires =\n    lxml\n    dbus-python; platform_system=='Linux'\n")

    assert requirements.get_declared_requirements(str(tmp_path)) == [
        "lxml", "dbus-python; platform_system=='Linux'"]


def test_a_requirements_file_wins_over_pyproject(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests\n")
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "nile"\ndependencies = ["other"]\n')

    assert requirements.get_declared_requirements(str(tmp_path))[0] == "-r"


def test_a_pyproject_without_dependencies_falls_through(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "tool"\n')
    (tmp_path / "setup.cfg").write_text("[options]\ninstall_requires =\n    lxml\n")

    assert requirements.get_declared_requirements(str(tmp_path)) == ["lxml"]


def test_nothing_declared_is_nothing(tmp_path):
    (tmp_path / "setup.py").write_text("from setuptools import setup\nsetup(install_requires = [])\n")

    assert requirements.get_declared_requirements(str(tmp_path)) == []


###########################################################
# Installing
###########################################################

@pytest.fixture
def pip_runs(monkeypatch):
    runs = []
    monkeypatch.setattr(requirements.programs, "is_tool_installed", lambda name: True)
    monkeypatch.setattr(requirements.programs, "get_tool_program", lambda name: "/venv/bin/pip")
    monkeypatch.setattr(requirements.command, "run_returncode_command",
                        lambda cmd, **kwargs: runs.append(cmd) or 0)
    return runs


def test_the_declared_requirements_go_into_the_venv(pip_runs, tmp_path):
    (tmp_path / "setup.cfg").write_text("[options]\ninstall_requires =\n    keyring\n")

    assert requirements.install_declared_requirements(str(tmp_path))
    assert pip_runs == [["/venv/bin/pip", "install", "keyring"]]


def test_shared_packages_are_not_upgraded(pip_runs, tmp_path):
    # The venv is shared, so one tool's install only fills what is missing
    (tmp_path / "requirements.txt").write_text("requests\n")

    requirements.install_declared_requirements(str(tmp_path))

    assert "--upgrade" not in pip_runs[0]


def test_nothing_declared_runs_nothing(pip_runs, tmp_path):
    assert requirements.install_declared_requirements(str(tmp_path))
    assert pip_runs == []
