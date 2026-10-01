# Imports
import inspect

# Third-party imports
import pytest

# Local imports
from joybox import command, config


###########################################################
# Capture runs
#
# A launch can record a screenshot or a video of itself. The capture region,
# length and overwrite policy all come from settings, and an existing capture
# is kept unless the settings say to replace it.
###########################################################

@pytest.fixture
def capturing(monkeypatch, isolated_settings, recording_command):
    state = {"screenshot": [], "video": []}

    def fake(kind, real):
        def capture(**kwargs):
            # Binding against the real signature catches a call it cannot accept.
            inspect.signature(real).bind(**kwargs)
            state[kind].append(kwargs)
            kwargs["run_func"]()
            return "captured"
        return capture

    monkeypatch.setattr(
        command.capture, "capture_screenshot_while_running",
        fake("screenshot", command.capture.capture_screenshot_while_running))
    monkeypatch.setattr(
        command.capture, "capture_video_while_running",
        fake("video", command.capture.capture_video_while_running))
    state["settings"] = isolated_settings
    state["runs"] = recording_command
    return state


def run(**kwargs):
    return command.run_capture_command(["/usr/bin/game"], **kwargs)


###########################################################
# No capture
###########################################################

def test_a_run_without_capture_just_runs(capturing):
    assert run() is True
    assert capturing["runs"].calls[0]["cmd"] == ["/usr/bin/game"]
    assert capturing["screenshot"] == [] and capturing["video"] == []


def test_a_failed_run_is_reported(capturing):
    capturing["runs"].returncode = 1

    assert run() is False


def test_the_run_flags_reach_the_command(capturing):
    run(verbose = True, pretend_run = True, exit_on_failure = True)

    assert capturing["runs"].calls[0]["kwargs"] == {
        "verbose": True, "pretend_run": True, "exit_on_failure": True}


###########################################################
# Screenshots
###########################################################

def test_a_screenshot_capture_uses_the_configured_region(capturing, tmp_path):
    capturing["settings"].set_value("UserData.Capture", "capture_origin_x", "10")
    capturing["settings"].set_value("UserData.Capture", "capture_origin_y", "20")
    capturing["settings"].set_value("UserData.Capture", "capture_resolution_w", "640")
    capturing["settings"].set_value("UserData.Capture", "capture_resolution_h", "480")

    assert run(capture_type = config.CaptureType.SCREENSHOT, capture_file = str(tmp_path / "shot.png")) == "captured"

    call = capturing["screenshot"][0]
    assert call["output_file"] == str(tmp_path / "shot.png")
    assert call["capture_origin"] == (10, 20)
    assert call["capture_resolution"] == (640, 480)
    assert call["time_units_type"] == config.UnitType.SECONDS
    assert len(capturing["runs"].calls) == 1


def test_a_screenshot_capture_uses_the_configured_timing(capturing, tmp_path):
    capturing["settings"].set_value("UserData.Capture", "capture_duration", "60")
    capturing["settings"].set_value("UserData.Capture", "capture_interval", "2")

    run(capture_type = config.CaptureType.SCREENSHOT, capture_file = str(tmp_path / "shot.png"))

    assert capturing["screenshot"][0]["time_duration"] == 60
    assert capturing["screenshot"][0]["time_interval"] == 2


def test_an_existing_screenshot_is_kept_by_default(capturing, tmp_path):
    existing = tmp_path / "shot.png"
    existing.write_text("")

    assert run(capture_type = config.CaptureType.SCREENSHOT, capture_file = str(existing)) is True
    assert capturing["screenshot"] == []


def test_an_existing_screenshot_is_replaced_when_configured(capturing, tmp_path):
    existing = tmp_path / "shot.png"
    existing.write_text("")
    capturing["settings"].set_value("UserData.Capture", "overwrite_screenshots", "True")

    run(capture_type = config.CaptureType.SCREENSHOT, capture_file = str(existing))

    assert len(capturing["screenshot"]) == 1


###########################################################
# Videos
###########################################################

def test_a_video_capture_uses_the_configured_region_and_rate(capturing, tmp_path):
    capturing["settings"].set_value("UserData.Capture", "capture_framerate", "60")
    capturing["settings"].set_value("UserData.Capture", "capture_duration", "90")

    assert run(capture_type = config.CaptureType.VIDEO, capture_file = str(tmp_path / "run.mp4")) == "captured"

    call = capturing["video"][0]
    assert call["output_file"] == str(tmp_path / "run.mp4")
    assert call["capture_origin"] == (0, 0)
    assert call["capture_resolution"] == (1920, 1080)
    assert call["capture_framerate"] == 60
    assert call["capture_duration"] == 90


def test_an_existing_video_is_kept_by_default(capturing, tmp_path):
    existing = tmp_path / "run.mp4"
    existing.write_text("")

    assert run(capture_type = config.CaptureType.VIDEO, capture_file = str(existing)) is True
    assert capturing["video"] == []


def test_an_existing_video_is_replaced_when_configured(capturing, tmp_path):
    existing = tmp_path / "run.mp4"
    existing.write_text("")
    capturing["settings"].set_value("UserData.Capture", "overwrite_videos", "True")

    run(capture_type = config.CaptureType.VIDEO, capture_file = str(existing))

    assert len(capturing["video"]) == 1


@pytest.mark.parametrize("capture_type", [config.CaptureType.SCREENSHOT, config.CaptureType.VIDEO])
def test_a_capture_passes_the_run_flags_through(capturing, tmp_path, capture_type):
    run(capture_type = capture_type, capture_file = str(tmp_path / "capture"),
        verbose = True, pretend_run = True, exit_on_failure = True)

    call = (capturing["screenshot"] + capturing["video"])[0]
    assert (call["verbose"], call["pretend_run"], call["exit_on_failure"]) == (True, True, True)
    assert capturing["runs"].calls[0]["kwargs"]["pretend_run"] is True
