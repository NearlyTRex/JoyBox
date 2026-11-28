# Imports
import importlib
import os
import select
import sys
import subprocess
import threading

# Local imports
from joybox import platform_info, cmdline
from joybox import commandrun
from joybox import config
from joybox import logger
from joybox import paths
from joybox import programs
from joybox import sandbox
from joybox import sandboxpaths
from joybox import sandboxprefix
from joybox.commandbase import (
    create_command_options,
    is_powershell_command,
    is_appimage_command,
    print_command)

# Get winpty, imported on first use since only Windows has it
def _get_winpty():
    return importlib.import_module("winpty")

# Get pty, imported on first use since Windows lacks it
def _get_pty():
    return importlib.import_module("pty")

###########################################################

# Start a command on a pseudo-terminal, closing this side's copy of the
# terminal once the child has it
def spawn_on_terminal(cmd, options, terminal_fd):
    try:
        return subprocess.Popen(
            cmd,
            shell = options.is_shell(),
            cwd = options.get_cwd(),
            env = options.get_env(),
            stdin = terminal_fd,
            stdout = terminal_fd,
            stderr = terminal_fd,
            close_fds = True)
    finally:
        os.close(terminal_fd)

# Check if prefix command
def is_prefix_command(cmd):
    return (
        sandbox.should_be_run_via_wine(cmd) or
        sandbox.should_be_run_via_sandboxie(cmd)
    )

###########################################################

# Wrap a command in "powershell -NoProfile -Command" unless it already starts with PowerShell
def setup_powershell_command(
    cmd,
    options = None):

    # Copy params
    new_cmd = cmd
    new_options = options.copy() if options else create_command_options()

    # Setup powershell command
    new_cmd = []
    if not is_powershell_command(cmd):
        new_cmd += ["powershell", "-NoProfile", "-Command"]
    new_cmd += cmdline.create_command_list(cmd)
    return (new_cmd, new_options)

# Point the XDG config, cache, data and state dirs at an AppImage's portable .home folder when it has one
def setup_appimage_command(
    cmd,
    options = None):

    # Copy params
    new_cmd = cmd
    new_options = options.copy() if options else create_command_options()

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

# Create the default Wine or Sandboxie prefix if the options lack a ready one, then rewrite the command to run inside it
def setup_prefix_command(
    cmd,
    options = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Copy params
    new_cmd = cmd
    new_options = options.copy() if options else create_command_options()

    # Create prefix if necessary
    if not new_options.has_ready_prefix():
        sandboxprefix.create_prefix(
            options = new_options,
            is_wine_prefix = sandbox.should_be_run_via_wine(cmd),
            is_sandboxie_prefix = sandbox.should_be_run_via_sandboxie(cmd),
            prefix_name = config.PrefixType.DEFAULT,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Setup prefix command
    new_cmd, new_options = sandbox.setup_prefix_command(
        cmd = new_cmd,
        options = new_options)
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
    options = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if not options:
        options = create_command_options()

    # Preprocess for powershell
    if is_powershell_command(cmd) or options.force_powershell():
        cmd, options = setup_powershell_command(
            cmd = cmd,
            options = options)

    # Preprocess for appimages
    if is_appimage_command(cmd) or options.force_appimage():
        cmd, options = setup_appimage_command(
            cmd = cmd,
            options = options)

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
    options = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if not options:
        options = create_command_options()

    # Postprocess for wine; Sandboxie has nothing to stop
    if sandbox.should_be_run_via_wine(cmd):
        sandboxprefix.cleanup_wine(
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Transfer files from sandbox if necessary
    if isinstance(options.get_output_paths(), list):
        for output_path in options.get_output_paths():
            sandboxpaths.transfer_from_sandbox(
                path = output_path,
                options = options,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

###########################################################

# Turn a command into an argument list with options, pre-processed unless the options say not to
def prepare_command(
    cmd,
    options,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    cmd = cmdline.create_command_list(cmd)
    if not options:
        options = create_command_options()
    if options.allow_processing():
        cmd, options = preprocess_command(
            cmd = cmd,
            options = options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return (cmd, options)

# Wait for blocking processes, then post-process
def finish_command(
    cmd,
    options,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    commandrun.wait_for_blocking_processes(options)
    if options.allow_processing():
        postprocess_command(
            cmd = cmd,
            options = options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Run a command through the PowerShell, AppImage and prefix wrapping, returning (output, return code);
# a pretend run returns ("", 0) and an OS error returns ("", 1)
def run_command(
    cmd,
    options = None,
    capture_output = True,
    log_stdout = False,
    log_stderr = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if pretend_run:
            return ("", 0)
        cmd, options = prepare_command(
            cmd = cmd,
            options = options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Run it, then post-process unless it was left running as a daemon
        output, returncode = commandrun.run_prepared_command(
            cmd = cmd,
            options = options,
            capture_output = capture_output,
            log_stdout = log_stdout,
            log_stderr = log_stderr,
            verbose = verbose)
        if options.allow_processing() and not options.is_daemon():
            postprocess_command(
                cmd = cmd,
                options = options,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        return (output, returncode)
    except (OSError, ValueError) as e:
        if verbose or exit_on_failure:
            logger.log_error(e, quit_program = exit_on_failure)
        return ("", 1)

# Captured output of a command, without logging its streams; empty on a pretend run or error
def run_output_command(
    cmd,
    options = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    output, _ = run_command(
        cmd = cmd,
        options = options,
        capture_output = True,
        log_stdout = False,
        log_stderr = False,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return output

# Exit code of a command whose stdout and stderr go to the log uncaptured; 0 on a pretend run
def run_returncode_command(
    cmd,
    options = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    _, returncode = run_command(
        cmd = cmd,
        options = options,
        capture_output = False,
        log_stdout = True,
        log_stderr = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return returncode

# Write output to stdout straight away
def _echo_output(output):
    sys.stdout.write(output)
    sys.stdout.flush()

# Echo the Windows pseudo-terminal's output live until the process ends
def _relay_winpty_output(pty_process):
    while pty_process.isalive():
        try:
            output = pty_process.read(1024)
            if output:
                _echo_output(output)
        except EOFError:
            break

# Forward the user's typed lines to the Windows pseudo-terminal until the process ends or is interrupted
def _forward_winpty_input(pty_process):
    try:
        while pty_process.isalive():
            user_input = sys.stdin.readline()
            if user_input:
                pty_process.write(user_input)
    except KeyboardInterrupt:
        pty_process.terminate()

# Run the command on a Windows pseudo-terminal, relaying output on a thread; its exit status
def _run_on_winpty(cmd, options):

    # Open psuedo-terminal
    with _get_winpty().PtyProcess.spawn(cmd, cwd = options.get_cwd(), env = options.get_env()) as pty_process:

        # Create thread to handle real-time I/O
        output_thread = threading.Thread(target = _relay_winpty_output, args = (pty_process,), daemon = True)
        output_thread.start()

        # Wait for process to complete
        _forward_winpty_input(pty_process)
        output_thread.join()
        return pty_process.exitstatus

# Echo whatever the pseudo-terminal has ready; False once it reaches the end of its stream
def _echo_ready_pty_output(master_fd):
    rlist, _, _ = select.select([master_fd], [], [], 0.1)
    if not (rlist and master_fd in rlist):
        return True
    output = os.read(master_fd, 1024).decode(errors = "ignore")
    if not output:
        return False
    _echo_output(output)
    return True

# Echo the pseudo-terminal's output live until its stream ends or fails
def _relay_pty_output(master_fd):
    while True:
        try:
            if not _echo_ready_pty_output(master_fd):
                break
        except (OSError, EOFError):
            break

# Forward a line the user has typed, when stdin has one ready, to the pseudo-terminal
def _forward_ready_input(master_fd):
    rlist, _, _ = select.select([sys.stdin], [], [], 0.1)
    if rlist and sys.stdin in rlist:
        user_input = sys.stdin.readline()
        if user_input:
            os.write(master_fd, user_input.encode())

# Forward typed input until the process ends; an interrupt terminates it and waits for it
def _forward_pty_input(proc, master_fd):
    try:
        while proc.poll() is None:
            _forward_ready_input(master_fd)
    except KeyboardInterrupt:
        proc.terminate()
        proc.wait()

# Run the command on a pseudo-terminal, relaying output on a thread; its exit code
def _run_on_pty(cmd, options):

    # Open pseudo-terminal
    master_fd, slave_fd = _get_pty().openpty()
    with spawn_on_terminal(cmd, options, slave_fd) as proc:

        # Create thread to handle real-time I/O
        output_thread = threading.Thread(target = _relay_pty_output, args = (master_fd,), daemon = True)
        output_thread.start()

        # Wait for process to complete
        _forward_pty_input(proc, master_fd)
        output_thread.join()
        os.close(master_fd)
        return proc.returncode

# Prepare and run the command on the platform's pseudo-terminal, then finish it; its exit code
def _run_prepared_interactive_command(cmd, options, verbose, pretend_run, exit_on_failure):
    cmd, options = prepare_command(
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

    # Run on a pseudo-terminal
    if platform_info.is_windows_platform():
        returncode = _run_on_winpty(cmd, options)
    else:
        returncode = _run_on_pty(cmd, options)

    # Wait for blocking processes, then post-process
    finish_command(
        cmd = cmd,
        options = options,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return returncode

# Run a command on a pseudo-terminal, relaying its output and the user's typed input live; returns its exit code
def run_interactive_command(
    cmd,
    options = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if not pretend_run:
            return _run_prepared_interactive_command(cmd, options, verbose, pretend_run, exit_on_failure)
        return 0
    except subprocess.CalledProcessError as e:
        if verbose or exit_on_failure:
            logger.log_error(e, quit_program = exit_on_failure)
        return e.returncode
    except (OSError, ValueError) as e:
        if verbose or exit_on_failure:
            logger.log_error(e, quit_program = exit_on_failure)
        return 1

###########################################################

# The installer type of the first marker found in the text, or None
def _find_installer_marker(window, installer_markers):
    for marker, installer_type in installer_markers:
        if marker in window:
            return installer_type
    return None

# Installer kind of a Windows setup file, from marker strings in its bytes; UNKNOWN when none matches
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
            installer_type = _find_installer_marker(window, installer_markers)
            if installer_type is not None:
                return installer_type
            carried = window[-overlap:]
    return config.InstallerType.UNKNOWN

# Argument list running an installer, with silent and target-dir flags for 7-Zip and WinRAR self-extractors
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

# DOSBox-X imgmount arguments putting each disc image on its own drive from D on;
# images beyond the last free drive letter are left unmounted with a warning
def get_dos_disc_mount_args(disc_images):
    mount_args = []
    for drive_letter, disc_image in zip(config.drives_regular, disc_images, strict = False):
        mount_args += ["-c", "imgmount %s \"%s\" -t iso" % (drive_letter, disc_image)]
    for disc_image in disc_images[len(config.drives_regular):]:
        logger.log_warning("No free drive letter to mount %s" % disc_image)
    return mount_args

# DOSBox-X with the named config file, the prefix's C drive and each of its CHD discs mounted
def _get_dosbox_mount_command(options, config_name):

    # Search for disc images
    disc_images = paths.build_file_list_by_extensions(options.get_prefix_dos_d_drive(), extensions = [".chd"])

    # Create launch command
    launch_cmd = [programs.get_emulator_program("DosBoxX")]

    # Add config file
    launch_cmd += [
        "-conf",
        programs.get_emulator_path_config_value("DosBoxX", config_name)
    ]

    # Add c drive mount
    if options.has_valid_prefix_dos_c_drive():
        launch_cmd += [
            "-c", "mount c \"%s\"" % options.get_prefix_dos_c_drive()
        ]

    # Add disc drive mounts
    launch_cmd += get_dos_disc_mount_args(disc_images)
    return launch_cmd

# DOSBox-X commands switching to the start drive, then into the start folder when there is one
def _get_dos_start_dir_args(start_letter, start_offset):
    start_dir_args = ["-c", "%s:" % start_letter]
    if paths.is_path_valid(start_offset):
        start_dir_args += ["-c", "cd %s" % start_offset]
    return start_dir_args

# The start program's file name, followed by its arguments when there are any
def _format_start_program(start_program, start_args):
    if isinstance(start_args, list) and len(start_args) > 0:
        return "%s %s" % (paths.get_filename_file(start_program), " ".join(start_args))
    return paths.get_filename_file(start_program)

# DOSBox-X arguments mounting the prefix's C drive and its CHD discs, then switching drive, folder and starting the program
def get_dos_launch_command(
    options,
    start_program = None,
    start_args = None,
    start_letter = "c",
    start_offset = None,
    fullscreen = False):

    # Get start args
    start_args = [] if start_args is None else start_args

    # Create launch command with its drives mounted
    launch_cmd = _get_dosbox_mount_command(options, "config_file")

    # Add initial launch params
    launch_cmd += _get_dos_start_dir_args(start_letter, start_offset)
    if paths.is_path_valid(start_program):
        launch_cmd += ["-c", "%s" % _format_start_program(start_program, start_args)]

    # Add other flags
    if fullscreen:
        launch_cmd += ["-fullscreen"]

    # Return launch command
    return launch_cmd

# DOSBox-X arguments with the Windows 3.1 config that mount the prefix drives and start the program with WIN RUNEXIT
def get_win31_launch_command(
    options,
    start_program = None,
    start_args = None,
    start_letter = "c",
    start_offset = None,
    fullscreen = False):

    # Get start args
    start_args = [] if start_args is None else start_args

    # Create launch command with its drives mounted
    launch_cmd = _get_dosbox_mount_command(options, "config_file_win31")

    # Add initial launch params
    launch_cmd += ["-c", r"SET PATH=%PATH%;C:\WINDOWS;"]
    launch_cmd += ["-c", r"SET TEMP=C:\WINDOWS\TEMP"]
    launch_cmd += _get_dos_start_dir_args(start_letter, start_offset)
    if paths.is_path_valid(start_program):
        launch_cmd += ["-c", "WIN RUNEXIT %s" % _format_start_program(start_program, start_args)]
        launch_cmd += ["-c", "EXIT"]

    # Add other flags
    if fullscreen:
        launch_cmd += ["-fullscreen"]

    # Return launch command
    return launch_cmd

# ScummVM arguments auto-detecting the game in the prefix's scumm folder, saving to its gamedata folder
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
