# Imports
import importlib
import os
import os.path
import threading

# Local imports
from joybox import command
from joybox import commandbase
from joybox import config
from joybox import paths
from joybox import settings
from joybox import validation
from joybox import logger
from joybox import programs
from joybox import sandbox
from joybox import sandboxpaths
from joybox import background
from joybox import process
from joybox import platform_info

# Get PIL.ImageGrab, imported on first use
def _get_image_grab():
    return importlib.import_module("PIL.ImageGrab")

# Grab the screen, or the region at origin of the given resolution, into an image file with Pillow; False when it fails
def capture_screenshot(
    output_file,
    capture_origin = None,
    capture_resolution = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check params
    validation.assert_is_valid_path(output_file, "output_file")

    # Get capture region
    capture_region = None
    if capture_origin and capture_resolution:
        capture_region = (
            capture_origin[0],
            capture_origin[1],
            capture_origin[0] + capture_resolution[0],
            capture_origin[1] + capture_resolution[1])

    # Capture screenshot
    if verbose:
        logger.log_info("Capturing screenshot to %s" % output_file)
    if pretend_run:
        return True
    image_grab = _get_image_grab()
    try:
        screenshot = image_grab.grab(bbox = capture_region)
        screenshot.save(output_file)
    except (OSError, ValueError) as e:
        if verbose or exit_on_failure:
            logger.log_error("Unable to capture screenshot to %s" % output_file)
            logger.log_error(e, quit_program = exit_on_failure)
        return False

    # Check result
    return os.path.exists(output_file)

# Run the function while the background job runs, stopping the job however it ends
def _run_with_background_job(run_func, background_job):
    background_job.start()
    try:
        return run_func()
    finally:
        background_job.stop()

# True when the run succeeded and the capture file exists, or would in a pretend run
def _check_capture_result(run_success, output_file, pretend_run):
    if not run_success:
        return False
    if pretend_run:
        return True
    return os.path.exists(output_file)

# Run a function while a background job re-grabs the screenshot every interval; True when it succeeds and the image exists
def capture_screenshot_while_running(
    run_func,
    output_file,
    time_duration,
    time_interval,
    time_units_type,
    capture_origin = None,
    capture_resolution = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check params
    validation.assert_callable(run_func, "run_func")

    # Create capture func
    def capture_func():
        capture_screenshot(
            output_file = output_file,
            capture_origin = capture_origin,
            capture_resolution = capture_resolution,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Create background job for capturing
    background_job = background.BackgroundJob(
        job_func = capture_func,
        units_exact = time_duration,
        units_type = time_units_type,
        sleep_interval = time_interval)

    # Run given function while capturing
    run_success = _run_with_background_job(run_func, background_job)

    # Check result
    return _check_capture_result(run_success, output_file, pretend_run)

# The last desktop audio monitor source pactl lists, or None when there is none
def _get_linux_audio_device(pretend_run):
    audio_device = None
    audio_sources = command.run_output_command(
        cmd = ["pactl", "list", "sources", "short"],
        verbose = False,
        pretend_run = pretend_run,
        exit_on_failure = False)
    for audio_source in audio_sources.splitlines():
        if "output" not in audio_source:
            continue
        if ".monitor" not in audio_source:
            continue
        audio_device = audio_source.split()[0]
    return audio_device

# FFMpeg inputs for the X11 screen at the origin, plus the desktop audio when there is a monitor source
def _get_linux_capture_sources(capture_origin, pretend_run):

    # Video
    sources = [
        "-f", "x11grab",
        "-draw_mouse", "0",
        "-i", ":0.0+%s,%s" % (capture_origin[0], capture_origin[1]),
    ]

    # Audio
    audio_device = _get_linux_audio_device(pretend_run)
    if audio_device:
        sources += [
            "-f", "pulse",
            "-ac", "2",
            "-i", str(audio_device)
        ]
    return sources

# FFMpeg input for the Windows desktop at the origin
def _get_windows_capture_sources(capture_origin):
    return [
        "-f", "gdigrab",
        "-draw_mouse", "0",
        "-offset_x", str(capture_origin[0]),
        "-offset_y", str(capture_origin[1]),
        "-i", "desktop",
    ]

# The FFMpeg screen recording command, or None after logging that the platform has no video source
def _build_capture_command(ffmpeg_tool, output_file, capture_origin, capture_resolution, capture_framerate, capture_duration, pretend_run):

    # Get capture command
    capture_cmd = [ffmpeg_tool]
    capture_cmd += [
        "-y",
        "-video_size", "%sx%s" % (capture_resolution[0], capture_resolution[1]),
        "-framerate", str(capture_framerate),
    ]

    # Add video/audio sources
    if platform_info.is_linux_platform():
        capture_cmd += _get_linux_capture_sources(capture_origin, pretend_run)
    elif platform_info.is_windows_platform():
        capture_cmd += _get_windows_capture_sources(capture_origin)
    else:
        logger.log_error("Video capture is not supported on this platform")
        return None

    # Add remaining options
    capture_cmd += [
        "-c:v", "h264_nvenc",
        "-cq:v", "20",
        "-t", str(capture_duration),
        output_file
    ]
    return capture_cmd

# Command options for FFMpeg writing the output file, run through its wine or sandboxie prefix when it needs one
def _get_capture_options(ffmpeg_tool, output_file):
    capture_options = commandbase.create_command_options(
        output_paths = [output_file],
        blocking_processes = [ffmpeg_tool])
    capture_options.setup_prefix(
        is_wine_prefix = sandbox.should_be_run_via_wine(ffmpeg_tool),
        is_sandboxie_prefix = sandbox.should_be_run_via_sandboxie(ffmpeg_tool),
        prefix_name = sandboxpaths.get_program_prefix_name("FFMpeg"))
    return capture_options

# Record the screen region, plus desktop audio on Linux, to an NVENC H.264 file with FFMpeg for the duration in seconds
def capture_video(
    output_file,
    capture_origin,
    capture_resolution,
    capture_framerate,
    capture_duration,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check params
    validation.assert_is_valid_path(output_file, "output_file")

    # Get tool
    ffmpeg_tool = programs.find_tool_program("FFMpeg")
    if not ffmpeg_tool:
        return False

    # Get capture command
    capture_cmd = _build_capture_command(
        ffmpeg_tool, output_file, capture_origin, capture_resolution, capture_framerate, capture_duration, pretend_run)
    if not capture_cmd:
        return False

    # Run capture command
    command.run_returncode_command(
        cmd = capture_cmd,
        options = _get_capture_options(ffmpeg_tool, output_file),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check result
    if pretend_run:
        return True
    return os.path.exists(output_file)

# Run the function while the thread records, then interrupt FFMpeg and wait for the thread
def _run_with_capture_thread(run_func, background_thread, ffmpeg_tool, pretend_run):
    background_thread.start()
    try:
        return run_func()
    finally:

        # Stop capture
        if not pretend_run:
            process.interrupt_active_named_processes([ffmpeg_tool])
        background_thread.join()

# Record the screen with FFMpeg on a thread while a function runs, interrupting FFMpeg when it returns
def capture_video_while_running(
    run_func,
    output_file,
    capture_origin,
    capture_resolution,
    capture_framerate,
    capture_duration,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check params
    validation.assert_callable(run_func, "run_func")

    # Get tool
    ffmpeg_tool = programs.find_tool_program("FFMpeg")
    if not ffmpeg_tool:
        return False

    # Create capture func
    def capture_func():
        capture_video(
            output_file = output_file,
            capture_origin = capture_origin,
            capture_resolution = capture_resolution,
            capture_framerate = capture_framerate,
            capture_duration = capture_duration,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Run given function while capturing on a background thread
    run_success = _run_with_capture_thread(run_func, threading.Thread(target = capture_func), ffmpeg_tool, pretend_run)

    # Check result
    return _check_capture_result(run_success, output_file, pretend_run)

# The [UserData.Capture] settings: timing, region, framerate and whether to overwrite existing captures
def _get_capture_settings():
    return {
        "duration": settings.get_integer_value("UserData.Capture", "capture_duration"),
        "interval": settings.get_integer_value("UserData.Capture", "capture_interval"),
        "origin": (
            settings.get_integer_value("UserData.Capture", "capture_origin_x"),
            settings.get_integer_value("UserData.Capture", "capture_origin_y")),
        "resolution": (
            settings.get_integer_value("UserData.Capture", "capture_resolution_w"),
            settings.get_integer_value("UserData.Capture", "capture_resolution_h")),
        "framerate": settings.get_integer_value("UserData.Capture", "capture_framerate"),
        "overwrite_screenshots": settings.get_bool_value("UserData.Capture", "overwrite_screenshots"),
        "overwrite_videos": settings.get_bool_value("UserData.Capture", "overwrite_videos"),
    }

# Run while capturing screenshots, or just run when the screenshot exists and is not to be overwritten
def _run_with_screenshots(run_start, capture_file, capture_settings, verbose, pretend_run, exit_on_failure):
    if paths.is_path_file(capture_file) and not capture_settings["overwrite_screenshots"]:
        return run_start()
    return capture_screenshot_while_running(
        run_func = run_start,
        output_file = capture_file,
        time_duration = capture_settings["duration"],
        time_interval = capture_settings["interval"],
        time_units_type = config.UnitType.SECONDS,
        capture_origin = capture_settings["origin"],
        capture_resolution = capture_settings["resolution"],
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Run while capturing video, or just run when the video exists and is not to be overwritten
def _run_with_video(run_start, capture_file, capture_settings, verbose, pretend_run, exit_on_failure):
    if paths.is_path_file(capture_file) and not capture_settings["overwrite_videos"]:
        return run_start()
    return capture_video_while_running(
        run_func = run_start,
        output_file = capture_file,
        capture_origin = capture_settings["origin"],
        capture_resolution = capture_settings["resolution"],
        capture_framerate = capture_settings["framerate"],
        capture_duration = capture_settings["duration"],
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Run a command while taking screenshots or video per the capture settings; existing captures are kept unless overwrite is set
def run_capture_command(
    cmd,
    options = commandbase.create_command_options(),
    capture_type = None,
    capture_file = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Blocking start method
    def run_start():
        code = command.run_returncode_command(
            cmd = cmd,
            options = options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return code == 0

    # Get capture info
    capture_settings = _get_capture_settings()

    # Screenshot capturing
    if capture_type == config.CaptureType.SCREENSHOT:
        return _run_with_screenshots(run_start, capture_file, capture_settings, verbose, pretend_run, exit_on_failure)

    # Video capturing
    if capture_type == config.CaptureType.VIDEO:
        return _run_with_video(run_start, capture_file, capture_settings, verbose, pretend_run, exit_on_failure)

    # No capture
    return run_start()
