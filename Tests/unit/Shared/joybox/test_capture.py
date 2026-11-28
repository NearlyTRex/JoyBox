# Imports
import inspect
import sys
import types

# Third-party imports
import pytest

# Local imports
from joybox import capture, config


###########################################################
# Captures
#
# Screenshots are grabbed in-process; videos are recorded by FFMpeg running
# alongside the game. The screen grab, the scheduler, FFMpeg and the process
# signals are all faked, so nothing touches the display or spawns a child.
###########################################################

###########################################################
# Screenshots
###########################################################

@pytest.fixture
def grabber(monkeypatch):
    state = {"regions": [], "error": None}

    class FakeImage:
        def save(self, path):
            with open(path, "w", encoding = "utf-8") as handle:
                handle.write("png")

    def grab(bbox = None):
        error = state["error"]
        if error:
            raise error
        state["regions"].append(bbox)
        return FakeImage()

    image_grab = types.SimpleNamespace(grab = grab)
    monkeypatch.setitem(sys.modules, "PIL", types.SimpleNamespace(ImageGrab = image_grab))
    monkeypatch.setitem(sys.modules, "PIL.ImageGrab", image_grab)
    return state


@pytest.fixture
def logged(monkeypatch):
    state = {"info": [], "errors": [], "quits": []}
    monkeypatch.setattr(capture.logger, "log_info", lambda message, **kwargs: state["info"].append(message))

    def log_error(message, quit_program = False, **kwargs):
        state["errors"].append(message)
        state["quits"].append(quit_program)

    monkeypatch.setattr(capture.logger, "log_error", log_error)
    return state


def test_a_screenshot_is_saved_to_the_output_file(grabber, tmp_path):
    output = tmp_path / "shot.png"

    assert capture.capture_screenshot(str(output)) is True
    assert output.read_text() == "png"


def test_a_screenshot_without_a_region_is_the_whole_screen(grabber, tmp_path):
    capture.capture_screenshot(str(tmp_path / "shot.png"))

    assert grabber["regions"] == [None]


def test_a_screenshot_region_runs_from_the_origin_by_the_resolution(grabber, tmp_path):
    capture.capture_screenshot(
        str(tmp_path / "shot.png"),
        capture_origin = (10, 20),
        capture_resolution = (640, 480))

    assert grabber["regions"] == [(10, 20, 650, 500)]


def test_a_pretend_screenshot_grabs_nothing(grabber, tmp_path):
    output = tmp_path / "shot.png"

    assert capture.capture_screenshot(str(output), pretend_run = True) is True
    assert grabber["regions"] == []
    assert not output.exists()


def test_a_verbose_screenshot_is_logged(grabber, logged, tmp_path):
    capture.capture_screenshot(str(tmp_path / "shot.png"), verbose = True)

    assert len(logged["info"]) == 1


def test_a_failed_grab_is_a_failed_screenshot(grabber, logged, tmp_path):
    grabber["error"] = OSError("no display")

    assert capture.capture_screenshot(str(tmp_path / "shot.png")) is False
    assert logged["errors"] == []


def test_a_failed_grab_quits_when_asked(grabber, logged, tmp_path):
    grabber["error"] = OSError("no display")

    capture.capture_screenshot(str(tmp_path / "shot.png"), exit_on_failure = True)

    assert logged["quits"][-1] is True


def test_a_verbose_failed_grab_is_logged_without_quitting(grabber, logged, tmp_path):
    grabber["error"] = OSError("no display")

    capture.capture_screenshot(str(tmp_path / "shot.png"), verbose = True)

    assert logged["errors"] and not any(logged["quits"])


def test_a_screenshot_needs_an_output_path(grabber):
    with pytest.raises(AssertionError):
        capture.capture_screenshot("")


###########################################################
# Screenshots while running
###########################################################

@pytest.fixture
def scheduler(monkeypatch):
    state = {"jobs": [], "events": []}

    class FakeJob:
        def __init__(self, job_func, units_exact = None, units_type = None, sleep_interval = 0):
            self.job_func = job_func
            self.units_exact = units_exact
            self.units_type = units_type
            self.sleep_interval = sleep_interval
            state["jobs"].append(self)

        def start(self):
            state["events"].append("start")

        def stop(self):
            state["events"].append("stop")

    monkeypatch.setattr(capture.background, "BackgroundJob", FakeJob)
    return state


def capture_while_running(output, run_func = None, **kwargs):
    return capture.capture_screenshot_while_running(
        run_func = run_func or (lambda: True),
        output_file = str(output),
        time_duration = 30,
        time_interval = 1,
        time_units_type = config.UnitType.SECONDS,
        **kwargs)


def test_the_game_runs_while_the_schedule_is_active(scheduler, tmp_path):
    capture_while_running(tmp_path / "shot.png", run_func = lambda: scheduler["events"].append("run"))

    assert scheduler["events"] == ["start", "run", "stop"]


def test_the_schedule_uses_the_given_timing(scheduler, tmp_path):
    capture_while_running(tmp_path / "shot.png")

    job = scheduler["jobs"][0]
    assert (job.units_exact, job.units_type, job.sleep_interval) == (30, config.UnitType.SECONDS, 1)


def test_the_schedule_stops_even_when_the_game_fails(scheduler, tmp_path):
    def crash():
        raise RuntimeError("game crashed")

    with pytest.raises(RuntimeError):
        capture_while_running(tmp_path / "shot.png", run_func = crash)

    assert scheduler["events"] == ["start", "stop"]


def test_each_scheduled_capture_grabs_the_region(scheduler, grabber, tmp_path):
    output = tmp_path / "shot.png"
    capture_while_running(output, capture_origin = (1, 2), capture_resolution = (3, 4))

    scheduler["jobs"][0].job_func()

    assert grabber["regions"] == [(1, 2, 4, 6)]
    assert output.exists()


def test_a_screenshot_run_reports_whether_a_screenshot_exists(scheduler, tmp_path):
    output = tmp_path / "shot.png"

    assert capture_while_running(output) is False
    output.write_text("png")
    assert capture_while_running(output) is True


def test_a_failed_game_fails_the_screenshot_run(scheduler, tmp_path):
    output = tmp_path / "shot.png"
    output.write_text("png")

    assert capture_while_running(output, run_func = lambda: False) is False


def test_a_pretend_screenshot_run_succeeds_without_a_screenshot(scheduler, grabber, tmp_path):
    assert capture_while_running(tmp_path / "shot.png", pretend_run = True) is True

    scheduler["jobs"][0].job_func()
    assert grabber["regions"] == []


def test_a_screenshot_run_needs_something_to_run(scheduler, tmp_path):
    with pytest.raises(AssertionError):
        capture.capture_screenshot_while_running(
            run_func = None,
            output_file = str(tmp_path / "shot.png"),
            time_duration = 30,
            time_interval = 1,
            time_units_type = config.UnitType.SECONDS)


###########################################################
# Videos
###########################################################

FFMPEG = "/tools/ffmpeg"

PACTL_SOURCES = "\n".join([
    "1\talsa_input.usb-mic\tPipeWire\ts16le 1ch 48000Hz\tSUSPENDED",
    "2\talsa_output.pci-speakers.monitor\tPipeWire\ts32le 2ch 48000Hz\tRUNNING",
    "3\talsa_output.virtual-sink\tPipeWire\ts32le 2ch 48000Hz\tIDLE",
])


@pytest.fixture
def ffmpeg(monkeypatch, recording_command):
    state = {"installed": True, "platform": "linux", "wine": False}
    monkeypatch.setattr(capture.programs, "is_tool_installed", lambda name: state["installed"] and name == "FFMpeg")
    monkeypatch.setattr(capture.programs, "get_tool_program", lambda name: FFMPEG)
    monkeypatch.setattr(capture.programs, "is_program_name_tool", lambda name, *args: name == "FFMpeg")
    monkeypatch.setattr(capture.programs, "get_tool_path_config_value", lambda tool, key: "/sandboxes/" + tool)
    monkeypatch.setattr(capture.platform_info, "is_linux_platform", lambda: state["platform"] == "linux")
    monkeypatch.setattr(capture.platform_info, "is_windows_platform", lambda: state["platform"] == "windows")
    monkeypatch.setattr(capture.sandbox, "should_be_run_via_wine", lambda cmd: state["wine"])
    monkeypatch.setattr(capture.sandbox, "should_be_run_via_sandboxie", lambda cmd: False)
    recording_command.output = PACTL_SOURCES
    state["runs"] = recording_command
    return state


def record_video(output, **kwargs):
    return capture.capture_video(
        output_file = str(output),
        capture_origin = (10, 20),
        capture_resolution = (640, 480),
        capture_framerate = 30,
        capture_duration = 60,
        **kwargs)


def ffmpeg_call(state):
    calls = [call for call in state["runs"].calls if call["cmd"][0] == FFMPEG]
    assert len(calls) == 1, state["runs"].calls
    return calls[0]


def test_no_video_is_recorded_without_ffmpeg(ffmpeg, logged, tmp_path):
    ffmpeg["installed"] = False

    assert record_video(tmp_path / "run.mp4") is False
    assert ffmpeg["runs"].calls == []
    assert logged["errors"]


def test_a_linux_video_grabs_the_x_display_at_the_origin(ffmpeg, tmp_path):
    record_video(tmp_path / "run.mp4")

    cmd = ffmpeg_call(ffmpeg)["cmd"]
    assert cmd[:6] == [FFMPEG, "-y", "-video_size", "640x480", "-framerate", "30"]
    assert ["-f", "x11grab", "-draw_mouse", "0", "-i", ":0.0+10,20"] == cmd[6:12]


def test_a_linux_video_records_the_output_monitor(ffmpeg, tmp_path):
    record_video(tmp_path / "run.mp4")

    cmd = ffmpeg_call(ffmpeg)["cmd"]
    assert ["-f", "pulse", "-ac", "2", "-i", "2"] == cmd[12:18]


def test_the_desktop_audio_device_is_the_output_monitor(ffmpeg):
    assert capture.get_linux_audio_device() == "2"


def test_a_linux_video_without_a_monitor_source_has_no_audio(ffmpeg, tmp_path):
    ffmpeg["runs"].output = "1\talsa_input.usb-mic\tPipeWire\ts16le 1ch 48000Hz\tSUSPENDED"

    record_video(tmp_path / "run.mp4")

    assert "pulse" not in ffmpeg_call(ffmpeg)["cmd"]


def test_a_windows_video_grabs_the_desktop_at_the_origin(ffmpeg, tmp_path):
    ffmpeg["platform"] = "windows"

    record_video(tmp_path / "run.mp4")

    cmd = ffmpeg_call(ffmpeg)["cmd"]
    assert ["-f", "gdigrab", "-draw_mouse", "0", "-offset_x", "10", "-offset_y", "20", "-i", "desktop"] == cmd[6:16]
    assert len(ffmpeg["runs"].calls) == 1


def test_an_unsupported_platform_records_nothing(ffmpeg, logged, tmp_path):
    ffmpeg["platform"] = "mac"

    assert record_video(tmp_path / "run.mp4") is False
    assert ffmpeg["runs"].calls == []
    assert logged["errors"]


def test_a_video_ends_with_its_length_and_output_file(ffmpeg, tmp_path):
    output = tmp_path / "run.mp4"

    record_video(output)

    cmd = ffmpeg_call(ffmpeg)["cmd"]
    assert cmd[-7:] == ["-c:v", "h264_nvenc", "-cq:v", "20", "-t", "60", str(output)]


def test_a_video_waits_for_ffmpeg_and_collects_its_output(ffmpeg, tmp_path):
    output = tmp_path / "run.mp4"

    record_video(output)

    options = ffmpeg_call(ffmpeg)["options"]
    assert options.get_output_paths() == [str(output)]
    assert options.get_blocking_processes() == [FFMPEG]


def test_a_native_ffmpeg_runs_outside_any_prefix(ffmpeg, tmp_path):
    record_video(tmp_path / "run.mp4")

    options = ffmpeg_call(ffmpeg)["options"]
    assert options.is_prefix() is False
    assert options.get_prefix_dir() is None


def test_a_wine_ffmpeg_runs_in_the_tool_prefix(ffmpeg, tmp_path):
    ffmpeg["wine"] = True

    record_video(tmp_path / "run.mp4")

    options = ffmpeg_call(ffmpeg)["options"]
    assert options.is_wine_prefix() is True
    assert options.get_prefix_name() == config.PrefixType.TOOL
    assert options.get_prefix_dir() == "/sandboxes/Wine/Tool"


def test_a_video_reports_whether_the_file_exists(ffmpeg, tmp_path):
    output = tmp_path / "run.mp4"

    assert record_video(output) is False
    output.write_text("mp4")
    assert record_video(output) is True


def test_a_pretend_video_succeeds_and_passes_the_flags_on(ffmpeg, tmp_path):
    assert record_video(tmp_path / "run.mp4", verbose = True, pretend_run = True, exit_on_failure = True) is True

    for call in ffmpeg["runs"].calls:
        assert call["kwargs"]["pretend_run"] is True
    assert ffmpeg_call(ffmpeg)["kwargs"] == {"verbose": True, "pretend_run": True, "exit_on_failure": True}


###########################################################
# Videos while running
###########################################################

@pytest.fixture
def recorder(monkeypatch, ffmpeg):
    state = {"videos": [], "events": [], "interrupted": []}

    def capture_video(**kwargs):
        state["videos"].append(kwargs)
        state["events"].append("record")

    monkeypatch.setattr(capture, "capture_video", capture_video)
    monkeypatch.setattr(
        capture.process, "interrupt_active_named_processes",
        lambda names: state["interrupted"].append(list(names)))
    state["ffmpeg"] = ffmpeg
    return state


def record_while_running(output, run_func = None, **kwargs):
    return capture.capture_video_while_running(
        run_func = run_func or (lambda: True),
        output_file = str(output),
        capture_origin = (10, 20),
        capture_resolution = (640, 480),
        capture_framerate = 30,
        capture_duration = 60,
        **kwargs)


def test_no_video_run_happens_without_ffmpeg(recorder, logged, tmp_path):
    recorder["ffmpeg"]["installed"] = False
    ran = []

    assert record_while_running(tmp_path / "run.mp4", run_func = lambda: ran.append(True)) is False
    assert ran == []
    assert recorder["videos"] == []


def test_the_recording_gets_the_capture_settings(recorder, tmp_path):
    record_while_running(tmp_path / "run.mp4", verbose = True)

    video = recorder["videos"][0]
    assert video["output_file"] == str(tmp_path / "run.mp4")
    assert video["capture_origin"] == (10, 20)
    assert video["capture_resolution"] == (640, 480)
    assert video["capture_framerate"] == 30
    assert video["capture_duration"] == 60
    assert video["verbose"] is True


def test_ffmpeg_is_interrupted_once_the_game_ends(recorder, tmp_path):
    record_while_running(tmp_path / "run.mp4")

    assert recorder["interrupted"] == [[FFMPEG]]


def test_ffmpeg_is_interrupted_even_when_the_game_fails(recorder, tmp_path):
    def crash():
        raise RuntimeError("game crashed")

    with pytest.raises(RuntimeError):
        record_while_running(tmp_path / "run.mp4", run_func = crash)

    assert recorder["interrupted"] == [[FFMPEG]]


def test_the_recording_has_finished_before_the_result_is_read(recorder, tmp_path, monkeypatch):
    output = tmp_path / "run.mp4"

    def slow_capture_video(**kwargs):
        import time
        time.sleep(0.05)
        output.write_text("mp4")

    monkeypatch.setattr(capture, "capture_video", slow_capture_video)

    assert record_while_running(output) is True


def test_a_video_run_without_a_file_fails(recorder, tmp_path):
    assert record_while_running(tmp_path / "run.mp4") is False


def test_a_failed_game_fails_the_video_run(recorder, tmp_path):
    output = tmp_path / "run.mp4"
    output.write_text("mp4")

    assert record_while_running(output, run_func = lambda: False) is False


def test_a_pretend_video_run_interrupts_nothing(recorder, tmp_path):
    assert record_while_running(tmp_path / "run.mp4", pretend_run = True) is True
    assert recorder["interrupted"] == []
    assert recorder["videos"][0]["pretend_run"] is True


def test_a_video_run_needs_something_to_run(recorder, tmp_path):
    with pytest.raises(AssertionError):
        capture.capture_video_while_running(
            run_func = None,
            output_file = str(tmp_path / "run.mp4"),
            capture_origin = (0, 0),
            capture_resolution = (1, 1),
            capture_framerate = 1,
            capture_duration = 1)


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
        capture, "capture_screenshot_while_running",
        fake("screenshot", capture.capture_screenshot_while_running))
    monkeypatch.setattr(
        capture, "capture_video_while_running",
        fake("video", capture.capture_video_while_running))
    state["settings"] = isolated_settings
    state["runs"] = recording_command
    return state


def run(**kwargs):
    return capture.run_capture_command(["/usr/bin/game"], **kwargs)


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


def test_the_capture_settings_are_read_from_the_config(capturing):
    capturing["settings"].set_value("UserData.Capture", "capture_framerate", "24")
    capturing["settings"].set_value("UserData.Capture", "capture_origin_x", "5")
    capturing["settings"].set_value("UserData.Capture", "capture_origin_y", "6")

    capture_settings = capture.get_capture_settings()

    assert capture_settings["framerate"] == 24
    assert capture_settings["origin"] == (5, 6)


def test_each_run_without_options_gets_its_own(capturing):
    run()
    run()

    first, second = (call["options"] for call in capturing["runs"].calls)
    assert first is not None
    assert first is not second


def test_given_options_reach_the_command(capturing):
    options = capture.commandbase.create_command_options(cwd = "/games")

    run(options = options)

    assert capturing["runs"].calls[0]["options"] is options


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
