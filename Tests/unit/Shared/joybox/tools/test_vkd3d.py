# Local imports
from joybox.tools import vkd3d
from tools_helpers import (
    assert_a_failed_step_stops_the_install,
    assert_nothing_runs_when_already_installed,
    assert_offline_matches_online,
    assert_setup_params_reach_every_step,
    installed_to,
)


def test_setup_installs_the_library(steps):
    assert vkd3d.VKD3D().setup()

    assert steps.names() == ["download_github_release"]
    assert installed_to(steps) == ["/install/VKD3D/lib"]


def test_a_failed_step_stops_the_install(steps):
    assert_a_failed_step_stops_the_install(steps, vkd3d.VKD3D())


def test_nothing_runs_when_already_installed(steps):
    assert_nothing_runs_when_already_installed(steps, vkd3d.VKD3D())


def test_setup_params_reach_every_step(steps):
    assert_setup_params_reach_every_step(steps, vkd3d.VKD3D())


def test_setup_offline_matches_the_online_install(steps):
    assert_offline_matches_online(steps, vkd3d.VKD3D())


def test_libs_are_found_by_bitness(steps, monkeypatch, tmp_path):
    for relative in ["x86/d3d12.dll", "x64/d3d12.dll", "x64/readme.txt"]:
        (tmp_path / relative).parent.mkdir(exist_ok = True)
        (tmp_path / relative).write_text("lib")
    monkeypatch.setattr(vkd3d.programs, "get_library_install_dir", lambda *args: str(tmp_path))

    assert vkd3d.get_libs32() == [str(tmp_path / "x86" / "d3d12.dll")]
    assert vkd3d.get_libs64() == [str(tmp_path / "x64" / "d3d12.dll")]
