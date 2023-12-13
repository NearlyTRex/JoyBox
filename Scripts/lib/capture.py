# Imports
import os, os.path
import sys
import threading

# Local imports
import config
import command
import system
import environment
import programs
import sandbox
import background

# Capture screenshot
def CaptureScreenshot(
    output_file,
    verbose = False,
    exit_on_failure = False):

    # Check params
    system.AssertIsValidPath(output_file, "output_file")

    # Capture screenshot
    import PIL.ImageGrab
    screenshot = Pil.ImageGrab.grab()
    screenshot.save(output_file)

    # Check result
    return os.path.exists(output_file)

# Capture screenshot while running
def CaptureScreenshotWhileRunning(
    run_func,
    output_file,
    time_duration,
    time_interval,
    time_units_type,
    verbose = False,
    exit_on_failure = False):

    # Check params
    system.AssertCallable(run_func, "run_func")

    # Create capture func
    def capture_func():
        CaptureScreenshot(
            output_file = output_file,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Create background job for capturing
    background_job = background.BackgroundJob(
        job_func = capture_func,
        units_exact = time_duration,
        units_type = time_units_type,
        sleep_interval = time_interval)

    # Run given function while capturing
    background_job.start()
    run_func()
    background_job.stop()

    # Check result
    return os.path.exists(output_file)

# Capture video
def CaptureVideo(
    output_file,
    capture_origin,
    capture_resolution,
    capture_framerate,
    capture_duration,
    verbose = False,
    exit_on_failure = False):

    # Check params
    system.AssertIsValidPath(output_file, "output_file")

    # Get prefix
    prefix_dir = programs.GetProgramPrefixDir("FFMpeg")
    prefix_name = programs.GetProgramPrefixName("FFMpeg")

    # Get tool
    ffmpeg_tool = None
    if programs.IsToolInstalled("FFMpeg"):
        ffmpeg_tool = programs.GetToolProgram("FFMpeg")
    if not ffmpeg_tool:
        return False

    # Get capture command
    capture_cmd = [ffmpeg_tool]
    capture_cmd += [
        "-y",
        "-video_size", "%sx%s" % (capture_resolution[0], capture_resolution[1]),
        "-framerate", str(capture_framerate),
    ]

    # Add linux video/audio sources
    if environment.IsLinuxPlatform():

        # Video
        capture_cmd += [
            "-f", "x11grab",
            "-draw_mouse", "0",
            "-i", ":0.0+%s,%s" % (capture_origin[0], capture_origin[1]),
        ]

        # Audio
        audio_device = None
        audio_sources = command.RunOutputCommand(
            cmd = ["pactl", "list", "sources", "short"],
            verbose = False,
            exit_on_failure = False)
        for audio_source in audio_sources.splitlines():
            if "output" not in audio_source:
                continue
            if ".monitor" not in audio_source:
                continue
            for audio_device_token in audio_source.split():
                audio_device = audio_device_token
                break
        if audio_device:
            capture_cmd += [
                "-f", "pulse",
                "-ac", "2",
                "-i", str(audio_device)
            ]

    # Add remaining options
    capture_cmd += [
        "-c:v", "h264_nvenc",
        "-cq:v", "20",
        "-t", str(capture_duration),
        output_file
    ]

    # Run capture command
    command.RunBlockingCommand(
        cmd = capture_cmd,
        options = command.CommandOptions(
            prefix_dir = prefix_dir,
            prefix_name = prefix_name,
            is_wine_prefix = sandbox.ShouldBeRunViaWine(ffmpeg_tool),
            is_sandboxie_prefix = sandbox.ShouldBeRunViaSandboxie(ffmpeg_tool),
            output_paths = [output_file],
            blocking_processes = [ffmpeg_tool]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(output_file)

# Capture video while running
def CaptureVideoWhileRunning(
    run_func,
    output_file,
    capture_origin,
    capture_resolution,
    capture_framerate,
    capture_duration,
    verbose = False,
    exit_on_failure = False):

    # Check params
    system.AssertCallable(run_func, "run_func")

    # Get tool
    ffmpeg_tool = None
    if programs.IsToolInstalled("FFMpeg"):
        ffmpeg_tool = programs.GetToolProgram("FFMpeg")
    if not ffmpeg_tool:
        return False

    # Create capture func
    def capture_func():
        CaptureVideo(
            output_file = output_file,
            capture_origin = capture_origin,
            capture_resolution = capture_resolution,
            capture_framerate = capture_framerate,
            capture_duration = capture_duration,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Create background thread for capturing
    background_thread = threading.Thread(target = capture_func)

    # Run given function while capturing
    background_thread.start()
    run_func()

    # Stop capture
    environment.InterruptActiveNamedProcesses([ffmpeg_tool])

    # Check result
    return os.path.exists(output_file)
