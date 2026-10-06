# Local imports
from joybox.tools import dxvk
from tools_helpers import (
    assert_a_failed_step_stops_the_install,
    assert_nothing_runs_when_already_installed,
    assert_offline_matches_online,
    assert_setup_params_reach_every_step,
    installed_to,
)


def test_setup_installs_the_library(steps):
    assert dxvk.DXVK().setup()

    assert steps.names() == ["download_github_release"]
    assert installed_to(steps) == ["/install/DXVK/lib"]


def test_a_failed_step_stops_the_install(steps):
    assert_a_failed_step_stops_the_install(steps, dxvk.DXVK())


def test_nothing_runs_when_already_installed(steps):
    assert_nothing_runs_when_already_installed(steps, dxvk.DXVK())


def test_setup_params_reach_every_step(steps):
    assert_setup_params_reach_every_step(steps, dxvk.DXVK())


def test_setup_offline_matches_the_online_install(steps):
    assert_offline_matches_online(steps, dxvk.DXVK())


def test_libs_are_found_by_bitness(steps, monkeypatch, tmp_path):
    for relative in ["x32/d3d11.dll", "x64/d3d11.dll", "x64/readme.txt"]:
        (tmp_path / relative).parent.mkdir(exist_ok = True)
        (tmp_path / relative).write_text("lib")
    monkeypatch.setattr(dxvk.programs, "get_library_install_dir", lambda *args: str(tmp_path))

    assert dxvk.get_libs32() == [str(tmp_path / "x32" / "d3d11.dll")]
    assert dxvk.get_libs64() == [str(tmp_path / "x64" / "d3d11.dll")]
