# Imports
import os
import sys
import contextlib
import subprocess
import threading

# Local imports
from joybox import platform_info, runtime, cmdline
import joybox.config as config
import joybox.logger as logger
import joybox.paths as paths
import joybox.programs as programs
import joybox.sandbox as sandbox
import joybox.capture as capture
import joybox.settings as settings
import joybox.process as process
from joybox.commandbase import (
    create_command_options as create_command_options,
    get_starter_command as get_starter_command,
    is_only_starter_command as is_only_starter_command,
    get_runnable_command_path as get_runnable_command_path,
    is_runnable_command as is_runnable_command,
    is_command_type_found as is_command_type_found,
    is_cached_game_command as is_cached_game_command,
    is_local_script_command as is_local_script_command,
    is_local_program_command as is_local_program_command,
    is_local_sandboxed_program_command as is_local_sandboxed_program_command,
    is_windows_executable_command as is_windows_executable_command,
    is_powershell_command as is_powershell_command,
    is_appimage_command as is_appimage_command,
    print_command as print_command)

###########################################################

# Check if prefix command
def is_prefix_command(cmd):
    return (
        sandbox.should_be_run_via_wine(cmd) or
        sandbox.should_be_run_via_sandboxie(cmd)
    )

###########################################################

# Setup powershell command
def setup_powershell_command(
    cmd,
    options = create_command_options(),
    verbose = False,
    exit_on_failure = False):

    # Copy params
    new_cmd = cmd
    new_options = options.copy()

    # Setup powershell command
    new_cmd = []
    if not is_powershell_command(cmd):
        new_cmd += ["powershell", "-NoProfile", "-Command"]
    new_cmd += cmdline.create_command_list(cmd)
    return (new_cmd, new_options)

# Setup appimage command
def setup_appimage_command(
    cmd,
    options = create_command_options(),
    verbose = False,
    exit_on_failure = False):

    # Copy params
    new_cmd = cmd
    new_options = options.copy()

    # Setup appimage command
    for cmd_segment in cmdline.create_command_list(cmd):
        if cmd_segment.lower().endswith(".appimage"):
            appimage_home_dir = os.path.realpath(cmd_segment + ".home")
            if os.path.exists(appimage_home_dir):
                new_options.set_env_var("XDG_CONFIG_HOME", paths.join_paths(appimage_home_dir, ".config"))
                new_options.set_env_var("XDG_CACHE_HOME", paths.join_paths(appimage_home_dir, ".cache"))
                new_options.set_env_var("XDG_DATA_HOME", paths.join_paths(appimage_home_dir, ".local", "share"))
                new_options.set_env_var("XDG_STATE_HOME", paths.join_paths(appimage_home_dir, ".local", "state"))
                break
    return (new_cmd, new_options)

# Setup prefix command
def setup_prefix_command(
    cmd,
    options = create_command_options(),
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Copy params
    new_cmd = cmd
    new_options = options.copy()

    # Create prefix if necessary
    if not new_options.has_ready_prefix():
        new_options.create_prefix(
            is_wine_prefix = sandbox.should_be_run_via_wine(cmd),
            is_sandboxie_prefix = sandbox.should_be_run_via_sandboxie(cmd),
            prefix_name = config.PrefixType.DEFAULT,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Setup prefix command
    new_cmd, new_options = sandbox.setup_prefix_command(
        cmd = new_cmd,
        options = new_options,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    new_cmd, new_options = sandbox.setup_prefix_environment(
        cmd = new_cmd,
        options = new_options,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return (new_cmd, new_options)

###########################################################

# Pre-process command
def preprocess_command(
    cmd,
    options = create_command_options(),
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Preprocess for powershell
    if is_powershell_command(cmd) or options.force_powershell():
        cmd, options = setup_powershell_command(
            cmd = cmd,
            options = options,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Preprocess for appimages
    if is_appimage_command(cmd) or options.force_appimage():
        cmd, options = setup_appimage_command(
            cmd = cmd,
            options = options,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Preprocess for prefix
    if is_prefix_command(cmd) or options.force_prefix():
        cmd, options = setup_prefix_command(
            cmd = cmd,
            options = options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Return any changes
    return (cmd, options)

# Post-process command
def postprocess_command(
    cmd,
    options = create_command_options(),
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Postprocess for wine
    if sandbox.should_be_run_via_wine(cmd):
        sandbox.cleanup_wine(
            cmd = cmd,
            options = options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Postprocess for sandboxie
    if sandbox.should_be_run_via_sandboxie(cmd):
        sandbox.cleanup_sandboxie(
            cmd = cmd,
            options = options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Transfer files from sandbox if necessary
    if isinstance(options.get_output_paths(), list):
        for output_path in options.get_output_paths():
            sandbox.transfer_from_sandbox(
                path = output_path,
                options = options,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

###########################################################

# Wait for blocking processes, then post-process
def finish_command(
    cmd,
    options,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if isinstance(options.get_blocking_processes(), list) and len(options.get_blocking_processes()) > 0:
        process.wait_for_named_processes(options.get_blocking_processes())
    if options.allow_processing():
        postprocess_command(
            cmd = cmd,
            options = options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Run a command, pumping its output streams in real time
def run_streamed_command(
    cmd,
    options,
    capture_output = True,
    log_stdout = False,
    log_stderr = False):

    # Determine output file handling
    stdout_path = options.get_stdout() if paths.is_path_valid(options.get_stdout()) else None
    stderr_path = options.get_stderr() if paths.is_path_valid(options.get_stderr()) else None

    # Determine stderr disposition:
    # - merge into stdout (OS-level, order-preserving) for include_stderr capture,
    # - pipe separately when streaming it live or writing it to a file,
    # - otherwise inherit the terminal (so it still shows up by default).
    pipe_stderr = log_stderr or stderr_path is not None
    capture_stderr = options.include_stderr() and capture_output
    if options.include_stderr() and not pipe_stderr:
        stderr_arg = subprocess.STDOUT
    elif pipe_stderr:
        stderr_arg = subprocess.PIPE
    else:
        stderr_arg = None

    # Get context stack
    with contextlib.ExitStack() as stack:
        stdout_target = stack.enter_context(open(stdout_path, "w")) if stdout_path else None
        stderr_target = stack.enter_context(open(stderr_path, "w")) if stderr_path else None

        # Open process
        proc = subprocess.Popen(
            cmd,
            shell = options.is_shell(),
            cwd = options.get_cwd(),
            env = options.get_env(),
            creationflags = options.get_creationflags(),
            stdout = subprocess.PIPE,
            stderr = stderr_arg,
            stdin = None,
            text = True,
            errors = "ignore",
            bufsize = 1)

        # readline() rather than "for line in pipe", which read-ahead-buffers
        # and defeats real-time streaming; an empty line is end of stream
        output_lines = []
        def pump(stream, capture, log, target):
            for line in iter(stream.readline, ""):
                if capture:
                    output_lines.append(line)
                if log:
                    logger.log_info(line.strip())
                if target:
                    target.write(line)
                    target.flush()

        # Run real-time I/O threads
        threads = [threading.Thread(
            target = pump,
            args = (proc.stdout, capture_output, log_stdout, stdout_target))]
        if pipe_stderr:
            threads.append(threading.Thread(
                target = pump,
                args = (proc.stderr, capture_stderr, log_stderr, stderr_target)))
        for t in threads:
            t.start()
        proc.wait()
        for t in threads:
            t.join()
    return (cmdline.clean_command_output("".join(output_lines).strip()), proc.returncode)

# Run command
def run_command(
    cmd,
    options = create_command_options(),
    capture_output = True,
    log_stdout = False,
    log_stderr = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        cmd = cmdline.create_command_list(cmd)
        if not options:
            options = create_command_options()
        if pretend_run:
            return ("", 0)

        # Pre-process command
        if options.allow_processing():
            cmd, options = preprocess_command(
                cmd = cmd,
                options = options,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Log command
        if verbose:
            print_command(cmd)

        # Handle shell commands
        if options.is_shell():
            cmd = cmdline.create_command_string(cmd)

        # Passthrough mode - inherit stdin/stdout/stderr directly (for TUI apps)
        if options.is_passthrough():
            returncode = subprocess.call(
                cmd,
                shell = options.is_shell(),
                cwd = options.get_cwd(),
                env = options.get_env())
            finish_command(
                cmd = cmd,
                options = options,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            return ("", returncode)

        # Daemon mode - detach and return without waiting or cleaning up after it
        if options.is_daemon():
            subprocess.Popen(
                cmd,
                shell = options.is_shell(),
                cwd = options.get_cwd(),
                env = options.get_env(),
                creationflags = options.get_creationflags() | getattr(subprocess, "DETACHED_PROCESS", 0),
                stdout = subprocess.DEVNULL,
                stderr = subprocess.DEVNULL,
                stdin = subprocess.DEVNULL,
                start_new_session = os.name != "nt")
            runtime.sleep_program(0.5)
            return ("", 0)

        # Suppressed output - discard streams, just wait
        if options.is_output_suppressed():
            proc = subprocess.Popen(
                cmd,
                shell = options.is_shell(),
                cwd = options.get_cwd(),
                env = options.get_env(),
                creationflags = options.get_creationflags(),
                stdout = subprocess.DEVNULL,
                stderr = subprocess.DEVNULL)
            proc.wait()
            finish_command(
                cmd = cmd,
                options = options,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            return ("", proc.returncode)

        # Run with streamed output
        output, returncode = run_streamed_command(
            cmd = cmd,
            options = options,
            capture_output = capture_output,
            log_stdout = log_stdout,
            log_stderr = log_stderr)
        finish_command(
            cmd = cmd,
            options = options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return (output, returncode)
    except Exception as e:
        if verbose or exit_on_failure:
            logger.log_error(e, quit_program = exit_on_failure)
        return ("", 1)

# Run output command
def run_output_command(
    cmd,
    options = create_command_options(),
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    output, returncode = run_command(
        cmd = cmd,
        options = options,
        capture_output = True,
        log_stdout = False,
        log_stderr = False,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return output

# Run returncode command
def run_returncode_command(
    cmd,
    options = create_command_options(),
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    output, returncode = run_command(
        cmd = cmd,
        options = options,
        capture_output = False,
        log_stdout = True,
        log_stderr = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return returncode

# Run interactive command
def run_interactive_command(
    cmd,
    options = create_command_options(),
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        cmd = cmdline.create_command_list(cmd)
        if not options:
            options = create_command_options()
        if not pretend_run:

            # Pre-process command
            if options.allow_processing():
                cmd, options = preprocess_command(
                    cmd = cmd,
                    options = options,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)

            # Log command
            if verbose:
                print_command(cmd)

            # Handle shell commands
            if options.is_shell():
                cmd = cmdline.create_command_string(cmd)

            # Create return code
            returncode = 0

            # Windows
            if platform_info.is_windows_platform():

                # Open psuedo-terminal
                from winpty import PtyProcess
                with PtyProcess.spawn(cmd, cwd = options.get_cwd(), env = options.get_env()) as pty_process:

                    # Reads from pseudo-terminal and displays it in real-time
                    def read_output():
                        while pty_process.isalive():
                            try:
                                output = pty_process.read(1024)
                                if output:
                                    sys.stdout.write(output)
                                    sys.stdout.flush()
                            except EOFError:
                                break

                    # Create thread to handle real-time I/O
                    output_thread = threading.Thread(target = read_output, daemon = True)
                    output_thread.start()

                    # Wait for process to complete
                    try:
                        while pty_process.isalive():
                            user_input = sys.stdin.readline()
                            if user_input:
                                pty_process.write(user_input)
                    except KeyboardInterrupt:
                        pty_process.terminate()
                    output_thread.join()
                    returncode = pty_process.exitstatus
            else:

                # Open pseudo-terminal
                import pty
                import select
                master_fd, slave_fd = pty.openpty()
                try:
                    proc = subprocess.Popen(
                        cmd,
                        shell = options.is_shell(),
                        cwd = options.get_cwd(),
                        env = options.get_env(),
                        stdin = slave_fd,
                        stdout = slave_fd,
                        stderr = slave_fd,
                        close_fds = True)
                finally:
                    os.close(slave_fd)

                # Reads from pseudo-terminal and displays it in real-time
                def read_output():
                    while True:
                        try:
                            rlist, _, _ = select.select([master_fd], [], [], 0.1)
                            if rlist and master_fd in rlist:
                                output = os.read(master_fd, 1024).decode(errors = "ignore")
                                if not output:
                                    break
                                sys.stdout.write(output)
                                sys.stdout.flush()
                        except (OSError, EOFError):
                            break

                # Create thread to handle real-time I/O
                output_thread = threading.Thread(target = read_output, daemon = True)
                output_thread.start()

                # Wait for process to complete
                try:
                    while proc.poll() is None:
                        rlist, _, _ = select.select([sys.stdin], [], [], 0.1)
                        if rlist and sys.stdin in rlist:
                            user_input = sys.stdin.readline()
                            if user_input:
                                os.write(master_fd, user_input.encode())
                except KeyboardInterrupt:
                    proc.terminate()
                    proc.wait()
                output_thread.join()
                os.close(master_fd)
                returncode = proc.returncode

            # Wait for blocking processes, then post-process
            finish_command(
                cmd = cmd,
                options = options,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            return returncode
        return 0
    except subprocess.CalledProcessError as e:
        if verbose or exit_on_failure:
            logger.log_error(e, quit_program = exit_on_failure)
        return e.returncode
    except Exception as e:
        if verbose or exit_on_failure:
            logger.log_error(e, quit_program = exit_on_failure)
        return 1

# Run capture command
def run_capture_command(
    cmd,
    options = create_command_options(),
    capture_type = None,
    capture_file = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Blocking start method
    def run_start():
        code = run_returncode_command(
            cmd = cmd,
            options = options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return (code == 0)

    # Get capture info
    capture_duration = settings.get_integer_value("UserData.Capture", "capture_duration")
    capture_interval = settings.get_integer_value("UserData.Capture", "capture_interval")
    capture_origin_x = settings.get_integer_value("UserData.Capture", "capture_origin_x")
    capture_origin_y = settings.get_integer_value("UserData.Capture", "capture_origin_y")
    capture_resolution_w = settings.get_integer_value("UserData.Capture", "capture_resolution_w")
    capture_resolution_h = settings.get_integer_value("UserData.Capture", "capture_resolution_h")
    capture_framerate = settings.get_integer_value("UserData.Capture", "capture_framerate")
    overwrite_screenshots = settings.get_bool_value("UserData.Capture", "overwrite_screenshots")
    overwrite_videos = settings.get_bool_value("UserData.Capture", "overwrite_videos")

    # Screenshot capturing
    if capture_type == config.CaptureType.SCREENSHOT:

        # Run while capturing screenshots
        if paths.is_path_file(capture_file) and not overwrite_screenshots:
            return run_start()
        else:
            return capture.capture_screenshot_while_running(
                run_func = run_start,
                output_file = capture_file,
                time_duration = capture_duration,
                time_interval = capture_interval,
                time_units_type = config.UnitType.SECONDS,
                capture_origin = (capture_origin_x, capture_origin_y),
                capture_resolution = (capture_resolution_w, capture_resolution_h),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

    # Video capturing
    elif capture_type == config.CaptureType.VIDEO:

        # Run while capturing video
        if paths.is_path_file(capture_file) and not overwrite_videos:
            return run_start()
        else:
            return capture.capture_video_while_running(
                run_func = run_start,
                output_file = capture_file,
                capture_origin = (capture_origin_x, capture_origin_y),
                capture_resolution = (capture_resolution_w, capture_resolution_h),
                capture_framerate = capture_framerate,
                capture_duration = capture_duration,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

    # No capture
    else:
        return run_start()

###########################################################

# Get installer type
def get_installer_type(installer_file):
    installer_markers = [
        ("Inno Setup", config.InstallerType.INNO),
        ("Nullsoft.NSIS.exehead", config.InstallerType.NSIS),
        ("InstallShieldSetup", config.InstallerType.INS),
        ("7-Zip", config.InstallerType.SEVENZIP),
        ("WinRAR SFX", config.InstallerType.WINRAR),
    ]
    overlap = max(len(marker) for marker, _ in installer_markers) - 1
    carried = ""
    with open(installer_file, "r", encoding="utf8", errors="ignore") as file:
        while True:
            file_contents = file.read(2048)
            if not file_contents:
                break
            window = carried + file_contents
            for marker, installer_type in installer_markers:
                if marker in window:
                    return installer_type
            carried = window[-overlap:]
    return config.InstallerType.UNKNOWN

# Get installer setup command
def get_installer_setup_command(
    installer_file,
    installer_type,
    install_dir = None,
    silent_install = True):

    # Create installer command
    installer_cmd = [installer_file]
    if installer_type == config.InstallerType.SEVENZIP:
        if silent_install:
            installer_cmd += ["-y"]
        if install_dir:
            installer_cmd += ["-o%s" % install_dir]
    elif installer_type == config.InstallerType.WINRAR:
        if silent_install:
            installer_cmd += ["-s2"]
        if install_dir:
            installer_cmd += ["-d%s" % install_dir]
    return installer_cmd

###########################################################

# Get dos launch command
def get_dos_launch_command(
    options,
    start_program = None,
    start_args = [],
    start_letter = "c",
    start_offset = None,
    fullscreen = False):

    # Search for disc images
    disc_images = paths.build_file_list_by_extensions(options.get_prefix_dos_d_drive(), extensions = [".chd"])

    # Create launch command
    launch_cmd = [programs.get_emulator_program("DosBoxX")]

    # Add config file
    launch_cmd += [
        "-conf",
        programs.get_emulator_path_config_value("DosBoxX", "config_file")
    ]

    # Add c drive mount
    if options.has_valid_prefix_dos_c_drive():
        launch_cmd += [
            "-c", "mount c \"%s\"" % options.get_prefix_dos_c_drive()
        ]

    # Add disc drive mounts
    if len(disc_images):
        disc_index = 0
        for disc_image in disc_images:
            launch_cmd += [
                "-c", "imgmount %s \"%s\" -t iso" % (config.drives_regular[disc_index], disc_image),
            ]
            disc_index += 1

    # Add initial launch params
    launch_cmd += ["-c", "%s:" % start_letter]
    if paths.is_path_valid(start_offset):
        launch_cmd += ["-c", "cd %s" % start_offset]
    if paths.is_path_valid(start_program):
        if isinstance(start_args, list) and len(start_args) > 0:
            launch_cmd += ["-c", "%s %s" % (paths.get_filename_file(start_program), " ".join(start_args))]
        else:
            launch_cmd += ["-c", "%s" % paths.get_filename_file(start_program)]

    # Add other flags
    if fullscreen:
        launch_cmd += ["-fullscreen"]

    # Return launch command
    return launch_cmd

# Get win31 launch command
def get_win31_launch_command(
    options,
    start_program = None,
    start_args = [],
    start_letter = "c",
    start_offset = None,
    fullscreen = False):

    # Search for disc images
    disc_images = paths.build_file_list_by_extensions(options.get_prefix_dos_d_drive(), extensions = [".chd"])

    # Create launch command
    launch_cmd = [programs.get_emulator_program("DosBoxX")]

    # Add config file
    launch_cmd += [
        "-conf",
        programs.get_emulator_path_config_value("DosBoxX", "config_file_win31")
    ]

    # Add c drive mount
    if options.has_valid_prefix_dos_c_drive():
        launch_cmd += [
            "-c", "mount c \"%s\"" % options.get_prefix_dos_c_drive()
        ]

    # Add disc drive mounts
    if len(disc_images):
        disc_index = 0
        for disc_image in disc_images:
            launch_cmd += [
                "-c", "imgmount %s \"%s\" -t iso" % (config.drives_regular[disc_index], disc_image),
            ]
            disc_index += 1

    # Add initial launch params
    launch_cmd += ["-c", r"SET PATH=%PATH%;C:\WINDOWS;"]
    launch_cmd += ["-c", r"SET TEMP=C:\WINDOWS\TEMP"]
    launch_cmd += ["-c", "%s:" % start_letter]
    if paths.is_path_valid(start_offset):
        launch_cmd += ["-c", "cd %s" % start_offset]
    if paths.is_path_valid(start_program):
        if isinstance(start_args, list) and len(start_args) > 0:
            launch_cmd += ["-c", "WIN RUNEXIT %s %s" % (paths.get_filename_file(start_program), " ".join(start_args))]
        else:
            launch_cmd += ["-c", "WIN RUNEXIT %s" % paths.get_filename_file(start_program)]
        launch_cmd += ["-c", "EXIT"]

    # Add other flags
    if fullscreen:
        launch_cmd += ["-fullscreen"]

    # Return launch command
    return launch_cmd

# Get scumm launch command
def get_scumm_launch_command(
    options,
    fullscreen = False):

    # Create launch command
    launch_cmd = [programs.get_emulator_program("ScummVM")]
    launch_cmd += [
        "--path=%s" % options.get_prefix_scumm_dir()
    ]
    launch_cmd += ["--auto-detect"]
    launch_cmd += [
        "--savepath=%s" % options.get_prefix_user_profile_gamedata_dir()
    ]
    if fullscreen:
        launch_cmd += ["--fullscreen"]

    # Return launch command
    return launch_cmd

###########################################################
