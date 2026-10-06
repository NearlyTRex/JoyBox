# Imports
import pytest

# Local imports
from cli_helpers import CommandHarness, Recorder, assert_entry_points
from joybox.cli import build_autoinstall_iso


###########################################################
# build_autoinstall_iso
#
# Command-line values override the configured install profile. --show_seed
# prints the seed without building anything; otherwise the image is built
# into the output directory, or the working directory when none is given.
###########################################################

@pytest.fixture
def tool(monkeypatch, isolated_settings):
    command = CommandHarness(monkeypatch, build_autoinstall_iso)
    auto = build_autoinstall_iso.autoinstall
    command.profile = {"version": "24.04", "hostname": "configured"}
    command.problems = []
    command.overlay = {"packages": ["vim"]}
    command.read_overlay = Recorder(result = lambda **kwargs: command.overlay)
    command.build = Recorder(result = True)
    monkeypatch.setattr(auto, "get_install_profile", lambda: dict(command.profile))
    monkeypatch.setattr(auto, "get_install_profile_problems", lambda profile: command.problems)
    monkeypatch.setattr(auto, "read_overlay_file", command.read_overlay)
    monkeypatch.setattr(auto, "build_user_data", lambda profile, overlay: "user-data %s %s" % (profile["hostname"], overlay))
    monkeypatch.setattr(auto, "build_meta_data", lambda profile: "meta-data %s" % profile["version"])
    monkeypatch.setattr(auto, "build_autoinstall_image", command.build)
    return command


###########################################################
# Building
###########################################################

def test_the_image_is_built_in_the_working_directory_by_default(tool, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    tool.main()

    call = tool.build.calls[0]
    assert call["output_file"] == str(tmp_path / "ubuntu-autoinstall.iso")
    assert call["profile"] == tool.profile
    assert (call["source_file"], call["overlay_file"], call["user_data_file"]) == (None, None, None)
    assert (call["verify"], call["verify_signature"]) == (True, True)
    assert tool.infos[-1] == ("Booting from it installs configured without asking anything (%d seconds to interrupt), then powers off."
                             % build_autoinstall_iso.autoinstall.boot_timeout)


def test_command_line_values_override_the_profile(tool, tmp_path):
    tool.main("-o", str(tmp_path), "-n", "server.iso", "-s", "ubuntu.iso", "-r", "26.04", "-t", "box", "-l",
        "-y", "overlay.yaml", "-d", "user-data.yaml", "-k", "-g", "-p")

    call = tool.build.calls[0]
    assert call["output_file"] == str(tmp_path / "server.iso")
    assert call["profile"] == {"version": "26.04", "hostname": "box", "serial_console": True}
    assert (call["source_file"], call["overlay_file"], call["user_data_file"]) == ("ubuntu.iso", "overlay.yaml", "user-data.yaml")
    assert (call["verify"], call["verify_signature"], call["pretend_run"]) == (False, False, True)
    assert "  sudo dd if=%s of=/dev/sdX bs=4M status=progress conv=fsync" % (tmp_path / "server.iso") in tool.infos


def test_a_failed_build_gives_no_instructions(tool, tmp_path):
    tool.build.result = False

    tool.main("-o", str(tmp_path))

    assert tool.errors == ["Unable to build autoinstall image"]
    assert tool.infos == []


###########################################################
# Showing the seed
###########################################################

def test_show_seed_prints_the_seed_without_building(tool, capsys):
    tool.main("-w", "-t", "box")

    assert capsys.readouterr().out == "user-data box None\nmeta-data 24.04\n"
    assert tool.build.calls == []
    assert tool.read_overlay.calls == []
    assert tool.errors == []


def test_show_seed_reads_the_configured_overlay(tool, capsys):
    tool.profile["overlay_file"] = "configured.yaml"

    tool.main("-w", "-v")

    assert tool.read_overlay.calls == [{"overlay_file": "configured.yaml", "verbose": True, "exit_on_failure": False}]
    assert "user-data configured {'packages': ['vim']}" in capsys.readouterr().out


def test_show_seed_prefers_the_given_overlay(tool):
    tool.profile["overlay_file"] = "configured.yaml"

    tool.main("-w", "-y", "given.yaml")

    assert tool.read_overlay.values("overlay_file") == ["given.yaml"]


def test_show_seed_stops_on_an_unreadable_overlay(tool, capsys):
    tool.overlay = None

    tool.main("-w", "-y", "broken.yaml")

    assert capsys.readouterr().out == ""


def test_show_seed_reports_profile_problems(tool, capsys):
    tool.problems = ["No password set"]

    tool.main("-w")

    assert tool.errors == ["No password set", "This configuration will not build until those are answered"]
    assert "meta-data" in capsys.readouterr().out


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, build_autoinstall_iso)
