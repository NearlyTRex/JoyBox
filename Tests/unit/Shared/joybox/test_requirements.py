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


def test_a_setup_cfg_without_install_requires_is_nothing(tmp_path):
    (tmp_path / "setup.cfg").write_text("[options]\npackages = find:\n")

    assert requirements.get_declared_requirements(str(tmp_path)) == []


def test_nothing_declared_is_nothing(tmp_path):
    (tmp_path / "setup.py").write_text("from setuptools import setup\nsetup(install_requires = [])\n")

    assert requirements.get_declared_requirements(str(tmp_path)) == []


###########################################################
# Setting up a tool's requirements
#
# Online setup installs them and keeps wheels beside the tool's backup; an
# offline setup installs from those wheels and never reaches the network.
###########################################################

@pytest.fixture
def tool(monkeypatch, tmp_path):
    lib_dir = tmp_path / "Tools" / "Nile" / "lib"
    lib_dir.mkdir(parents = True)
    wheels_dir = tmp_path / "Locker" / "Nile" / "wheels"
    runs = []
    monkeypatch.setattr(requirements.programs, "get_library_install_dir", lambda name, platform: str(lib_dir))
    monkeypatch.setattr(requirements.programs, "get_library_backup_dir", lambda name, platform: str(wheels_dir))
    monkeypatch.setattr(requirements.programs, "is_tool_installed", lambda name: True)
    monkeypatch.setattr(requirements.programs, "get_tool_program", lambda name: "/venv/bin/pip")
    monkeypatch.setattr(requirements.command, "run_returncode_command",
                        lambda cmd, **kwargs: runs.append(cmd) or 0)
    return lib_dir, wheels_dir, runs


def test_online_setup_installs_then_keeps_wheels(tool):
    lib_dir, wheels_dir, runs = tool
    (lib_dir / "requirements.txt").write_text("zstandard\n")

    assert requirements.setup_tool_requirements("Nile")
    assert runs == [
        ["/venv/bin/pip", "install", "-r", str(lib_dir / "requirements.txt")],
        ["/venv/bin/pip", "wheel", "--wheel-dir", str(wheels_dir), "-r", str(lib_dir / "requirements.txt")]]


def test_online_setup_does_not_upgrade_the_shared_venv(tool):
    lib_dir, _, runs = tool
    (lib_dir / "requirements.txt").write_text("requests\n")

    requirements.setup_tool_requirements("Nile")

    assert all("--upgrade" not in run for run in runs)


def test_online_setup_replaces_the_kept_wheels(tool):
    lib_dir, wheels_dir, _ = tool
    (lib_dir / "requirements.txt").write_text("zstandard\n")
    wheels_dir.mkdir(parents = True)
    (wheels_dir / "stale-1.0-py3-none-any.whl").write_text("old")

    requirements.setup_tool_requirements("Nile")

    assert not (wheels_dir / "stale-1.0-py3-none-any.whl").exists()


def test_offline_setup_installs_only_from_the_kept_wheels(tool):
    lib_dir, wheels_dir, runs = tool
    (lib_dir / "requirements.txt").write_text("zstandard\n")
    wheels_dir.mkdir(parents = True)

    assert requirements.setup_tool_requirements_offline("Nile")
    assert runs == [["/venv/bin/pip", "install", "--no-index", "--find-links", str(wheels_dir),
                     "-r", str(lib_dir / "requirements.txt")]]


def test_offline_setup_without_wheels_still_stays_offline(tool):
    # A backup made before wheels were kept only works if they are installed
    lib_dir, _, runs = tool
    (lib_dir / "requirements.txt").write_text("zstandard\n")

    requirements.setup_tool_requirements_offline("Nile")

    assert runs == [["/venv/bin/pip", "install", "--no-index", "-r", str(lib_dir / "requirements.txt")]]


def test_a_tool_that_declares_nothing_runs_nothing(tool):
    _, _, runs = tool

    assert requirements.setup_tool_requirements("Nile")
    assert requirements.setup_tool_requirements_offline("Nile")
    assert runs == []


def test_a_failed_install_fails_the_setup(tool, monkeypatch):
    lib_dir, _, _ = tool
    (lib_dir / "requirements.txt").write_text("zstandard\n")
    monkeypatch.setattr(requirements.command, "run_returncode_command", lambda cmd, **kwargs: 1)

    assert not requirements.setup_tool_requirements("Nile")
    assert not requirements.setup_tool_requirements_offline("Nile")


def test_a_missing_venv_pip_fails_the_setup(tool, monkeypatch):
    lib_dir, _, runs = tool
    (lib_dir / "requirements.txt").write_text("zstandard\n")
    monkeypatch.setattr(requirements.programs, "is_tool_installed", lambda name: False)

    assert not requirements.setup_tool_requirements("Nile")
    assert runs == []


def test_failing_to_keep_wheels_fails_the_setup(tool, monkeypatch):
    lib_dir, _, runs = tool
    (lib_dir / "requirements.txt").write_text("zstandard\n")
    monkeypatch.setattr(requirements.command, "run_returncode_command",
                        lambda cmd, **kwargs: runs.append(cmd) or int("wheel" in cmd))

    assert not requirements.setup_tool_requirements("Nile")
    assert runs[-1][1] == "wheel"
