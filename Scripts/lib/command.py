# Imports
import os
import sys
import re
import subprocess
import getpass
import shutil
import copy
import threading

# Local imports
import config
import system
import logger
import paths
import environment
import commandoptions
import programs
import sandbox
import strings
import capture
import ini
import process

###########################################################

# Create command options
def create_command_options(*args, **kwargs):
    return commandoptions.CommandOptions(*args, **kwargs)

# Create command string
def create_command_string(cmd):
    if not cmd:
        return ""
    if len(cmd) == 0:
        return ""
    if isinstance(cmd, str):
        return copy.deepcopy(cmd)
    if isinstance(cmd, list):
        cmd_str = ""
        for cmd_segment in cmd:
            if " " in cmd_segment:
                cmd_str += " " + "\"" + cmd_segment + "\""
            else:
                cmd_str += " " + cmd_segment
        cmd_str = cmd_str.strip()
        return cmd_str
    return ""

# Create command list
def create_command_list(cmd):
    if not cmd:
        return []
    if len(cmd) == 0:
        return []
    if isinstance(cmd, list):
        return copy.deepcopy(cmd)
    if isinstance(cmd, str):
        cmd = cmd.replace(" ", config.token_command_split)
        for quoted_substring in strings.split_by_enclosed_substrings(cmd, "\"", "\""):
            cmd = cmd.replace(quoted_substring, quoted_substring.replace(config.token_command_split, " "))
        return cmd.split(config.token_command_split)
    return []

###########################################################

# Clean command output
def clean_command_output(output):
    try:
        return output.decode("utf-8", "ignore")
    except:
        return output

###########################################################

# Get starter command
def get_starter_command(cmd):
    cmd_list = create_command_list(cmd)
    if len(cmd_list) == 0:
        return ""
    return cmd_list[0]

# Check if only starter command
def is_only_starter_command(cmd):
    cmd_list = create_command_list(cmd)
    return len(cmd_list) == 1

###########################################################

# Get runnable command path
def get_runnable_command_path(cmd, search_dirs = []):
    for search_dir in search_dirs:
        potential_paths = [paths.join_paths(search_dir, cmd)]
        for cmd_ext in config.WindowsProgramFileType.cvalues():
            potential_paths.append(paths.join_paths(search_dir, cmd + cmd_ext))
        for potential_path in potential_paths:
            verified_path = shutil.which(potential_path)
            if verified_path:
                return verified_path
    return shutil.which(cmd)

# Check if runnable command
def is_runnable_command(cmd, search_dirs = []):
    cmd_path = get_runnable_command_path(cmd, search_dirs)
    if not cmd_path:
        return False
    return True

###########################################################

# Check if command type is found
def is_command_type_found(cmd, cmd_exts = [], search_start = 0, search_len = -1):
    cmd_list = create_command_list(cmd)
    for cmd_index in range(len(cmd_list)):
        cmd_segment = cmd_list[cmd_index]
        is_found = False
        for ext in cmd_exts:
            if cmd_segment.lower().endswith(ext):
                is_found = True
                break
        is_in_range = True
        if search_start >= 0 and search_start < len(cmd_segment) and search_len > 0:
            is_in_range = (cmd_index >= search_start) and (cmd_index < search_start + search_len)
        if is_found and is_in_range:
            return True
    return False

###########################################################

# Check if cached game command
def is_cached_game_command(cmd):
    starter_cmd = os.path.normpath(get_starter_command(cmd)).lower()
    cached_dir = os.path.normpath(environment.get_cache_gaming_root_dir()).lower()
    return starter_cmd.startswith(cached_dir)

# Check if local script command
def is_local_script_command(cmd):
    starter_cmd = os.path.normpath(get_starter_command(cmd)).lower()
    scripts_dir = os.path.normpath(environment.get_scripts_bin_dir()).lower()
    return starter_cmd.startswith(scripts_dir)

# Check if local program command
def is_local_program_command(cmd):
    starter_cmd = get_starter_command(cmd)
    is_tool = programs.is_program_path_tool(starter_cmd)
    is_emulator = programs.is_program_path_emulator(starter_cmd)
    return is_tool or is_emulator

# Check if local sandboxed program command
def is_local_sandboxed_program_command(cmd):
    starter_cmd = get_starter_command(cmd)
    is_sandboxed_tool = programs.is_program_path_sandboxed_tool(starter_cmd)
    is_sandboxed_emulator = programs.is_program_path_sandboxed_emulator(starter_cmd)
    return is_sandboxed_tool or is_sandboxed_emulator

# Check if windows executable command
def is_windows_executable_command(cmd):
    return is_command_type_found(
        cmd = get_starter_command(cmd),
        cmd_exts = config.WindowsProgramFileType.cvalues())

# Check if powershell command
def is_powershell_command(cmd):
    starter_cmd = os.path.normpath(get_starter_command(cmd)).lower()
    return (
        starter_cmd.startswith("powershell") or
        starter_cmd.endswith("powershell") or
        starter_cmd.endswith("powershell.exe")
    )

# Check if appimage command
def is_appimage_command(cmd):
    starter_cmd = os.path.normpath(get_starter_command(cmd)).lower()
    return starter_cmd.endswith("appimage")

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
    new_cmd += create_command_list(cmd)
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
    for cmd_segment in create_command_list(cmd):
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
        exit_on_failure = exit_on_failure)
    new_cmd, new_options = sandbox.setup_prefix_environment(
        cmd = new_cmd,
        options = new_options,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    return (new_cmd, new_options)

###########################################################

# Pre-process command
def preprocess_command(
    cmd,
    options = create_command_options(),
    verbose = False,
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
            exit_on_failure = exit_on_failure)

    # Return any changes
    return (cmd, options)

# Post-process command
def postprocess_command(
    cmd,
    options = create_command_options(),
    verbose = False,
    exit_on_failure = False):

    # Postprocess for wine
    if sandbox.should_be_run_via_wine(cmd):
        sandbox.cleanup_wine(
            cmd = cmd,
            options = options,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Postprocess for sandboxie
    if sandbox.should_be_run_via_sandboxie(cmd):
        sandbox.cleanup_sandboxie(
            cmd = cmd,
            options = options,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Transfer files from sandbox if necessary
    if isinstance(options.get_output_paths(), list):
        for output_path in options.get_output_paths():
            sandbox.transfer_from_sandbox(
                path = output_path,
                options = options,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

###########################################################

# Mask sensitive arguments in command
def mask_sensitive_args(cmd):
    sensitive_flags = [
        "--passphrase",
        "--password",
        "--token",
        "--secret"
    ]
    if isinstance(cmd, str):
        for flag in sensitive_flags:
            if flag in cmd:
                cmd = re.sub(f"{flag}\\s+\\S+", f"{flag} ****", cmd)
        return cmd
    if isinstance(cmd, list):
        masked = []
        skip_next = False
        for arg in cmd:
            if skip_next:
                masked.append("****")
                skip_next = False
            elif arg in sensitive_flags:
                masked.append(arg)
                skip_next = True
            else:
                masked.append(arg)
        return masked
    return cmd

# Print command
def print_command(cmd):
    masked_cmd = mask_sensitive_args(cmd)
    if isinstance(masked_cmd, str):
        logger.log_info(masked_cmd)
    if isinstance(masked_cmd, list):
        logger.log_info(" ".join(masked_cmd))

###########################################################

# Run output command
def run_output_command(
    cmd,
    options = create_command_options(),
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        cmd = create_command_list(cmd)
        if not options:
            options = create_command_options()
        if not pretend_run:

            # Pre-process command
            if options.allow_processing():
                cmd, options = preprocess_command(
                    cmd = cmd,
                    options = options,
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)

            # Log command
            if verbose:
                print_command(cmd)

            # Handle shell commands
            if options.is_shell():
                cmd = create_command_string(cmd)

            # Run process
            output = ""
            if options.include_stderr():
                output = subprocess.run(
                    cmd,
                    shell = options.is_shell(),
                    cwd = options.get_cwd(),
                    env = options.get_env(),
                    creationflags = options.get_creationflags(),
                    stdout = subprocess.PIPE,
                    stderr = subprocess.STDOUT).stdout
            else:
                output = subprocess.run(
                    cmd,
                    shell = options.is_shell(),
                    cwd = options.get_cwd(),
                    env = options.get_env(),
                    creationflags = options.get_creationflags(),
                    stdout = subprocess.PIPE).stdout

            # Wait for any other blocking processes
            if isinstance(options.get_blocking_processes(), list) and len(options.get_blocking_processes()) > 0:
                process.wait_for_named_processes(options.get_blocking_processes())

            # Post-process command
            if options.allow_processing():
                postprocess_command(
                    cmd = cmd,
                    options = options,
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)
            return clean_command_output(output.strip())
        return ""
    except subprocess.CalledProcessError as e:
        if verbose:
            logger.log_error(e)
        elif exit_on_failure:
            logger.log_error(e, quit_program = True)
        if options.include_stderr():
            return e.output
        return ""
    except Exception as e:
        if verbose:
            logger.log_error(e)
        elif exit_on_failure:
            logger.log_error(e, quit_program = True)
        return ""

# Run returncode command
def run_returncode_command(
    cmd,
    options = create_command_options(),
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        cmd = create_command_list(cmd)
        if not options:
            options = create_command_options()
        if not pretend_run:

            # Pre-process command
            if options.allow_processing():
                cmd, options = preprocess_command(
                    cmd = cmd,
                    options = options,
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)

            # Log command
            if verbose:
                print_command(cmd)

            # Handle shell commands
            if options.is_shell():
                cmd = create_command_string(cmd)

            # Determine output file handling
            stdout_target = None
            stderr_target = None
            if paths.is_path_valid(options.get_stdout()):
                stdout_target = open(options.get_stdout(), "w")
            if paths.is_path_valid(options.get_stderr()):
                stderr_target = open(options.get_stderr(), "w")

            # Open process
            proc = subprocess.Popen(
                cmd,
                shell = options.is_shell(),
                cwd = options.get_cwd(),
                env = options.get_env(),
                creationflags = options.get_creationflags() if not options.is_daemon() else (
                    subprocess.DETACHED_PROCESS if os.name == 'nt' else 0
                ),
                stdout = subprocess.DEVNULL if (options.is_daemon() or options.is_output_suppressed()) else subprocess.PIPE,
                stderr = subprocess.DEVNULL if (options.is_daemon() or options.is_output_suppressed()) else subprocess.PIPE,
                stdin = subprocess.DEVNULL if options.is_daemon() else None,
                preexec_fn = os.setsid if options.is_daemon() and os.name != 'nt' else None,
                text = True,
                bufsize = 1)

            # Skip I/O threads if running as daemon or output is suppressed
            if not options.is_daemon() and not options.is_output_suppressed():

                # Reads from process output and logs it while writing to a file if needed
                def handle_output(pipe, log_func, file_target):
                    while True:
                        line = pipe.readline()
                        if not line and proc.poll() is not None:
                            break
                        if line:
                            log_func(line.strip())
                            if file_target:
                                file_target.write(line)
                                file_target.flush()

                # Reads user input and forwards it to the subprocess
                def handle_input():
                    while proc.poll() is None:
                        try:
                            user_input = sys.stdin.readline()
                            if user_input:
                                proc.stdin.write(user_input)
                                proc.stdin.flush()
                        except EOFError:
                            break

                # Create threads to handle real-time I/O
                stdout_thread = threading.Thread(target = handle_output, args = (proc.stdout, logger.log_info, stdout_target))
                stderr_thread = threading.Thread(target = handle_output, args = (proc.stderr, logger.log_info, stderr_target))
                stdout_thread.start()
                stderr_thread.start()

                # Wait for process to complete
                proc.wait()
                stdout_thread.join()
                stderr_thread.join()

            else:

                # For suppressed output, still wait for process to complete
                # For daemon, just sleep a tiny bit to allow startup before moving on
                if options.is_output_suppressed():
                    proc.wait()
                else:
                    system.sleep_program(0.5)

            # Close file handles if used
            if stdout_target:
                stdout_target.close()
            if stderr_target:
                stderr_target.close()

            # Wait for any other blocking processes
            if isinstance(options.get_blocking_processes(), list) and len(options.get_blocking_processes()) > 0:
                process.wait_for_named_processes(options.get_blocking_processes())

            # Post-process command
            if options.allow_processing():
                postprocess_command(
                    cmd = cmd,
                    options = options,
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)
            return 0 if options.is_daemon() else proc.returncode
        return 0
    except subprocess.CalledProcessError as e:
        if verbose:
            logger.log_error(e)
        elif exit_on_failure:
            logger.log_error(e, quit_program = True)
        return e.returncode
    except Exception as e:
        if verbose:
            logger.log_error(e)
        elif exit_on_failure:
            logger.log_error(e, quit_program = True)
        return 1

# Run interactive command
def run_interactive_command(
    cmd,
    options = create_command_options(),
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        cmd = create_command_list(cmd)
        if not options:
            options = create_command_options()
        if not pretend_run:

            # Pre-process command
            if options.allow_processing():
                cmd, options = preprocess_command(
                    cmd = cmd,
                    options = options,
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)

            # Log command
            if verbose:
                print_command(cmd)

            # Handle shell commands
            if options.is_shell():
                cmd = create_command_string(cmd)

            # Create return code
            returncode = 0

            # Windows
            if environment.is_windows_platform():

                # Open psuedo-terminal
                import pywinpty
                with pywinpty.PtyProcess.spawn(cmd) as process:

                    # Reads from pseudo-terminal and displays it in real-time
                    def read_output():
                        while process.isalive():
                            try:
                                output = process.read(1024)
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
                        while process.isalive():
                            user_input = sys.stdin.readline()
                            if user_input:
                                process.write(user_input)
                    except KeyboardInterrupt:
                        process.terminate()
                    output_thread.join()
                    returncode = process.exitstatus
            else:

                # Open pseudo-terminal
                import pty
                import select
                master_fd, slave_fd = pty.openpty()
                proc = subprocess.Popen(
                    cmd,
                    stdin = slave_fd,
                    stdout = slave_fd,
                    stderr = slave_fd,
                    text = True,
                    bufsize = 1,
                    close_fds = True)
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
                output_thread.join()
                returncode = proc.returncode

            # Wait for any other blocking processes
            if isinstance(options.get_blocking_processes(), list) and len(options.get_blocking_processes()) > 0:
                process.wait_for_named_processes(options.get_blocking_processes())

            # Post-process command
            if options.allow_processing():
                postprocess_command(
                    cmd = cmd,
                    options = options,
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)
            return returncode
        return 0
    except subprocess.CalledProcessError as e:
        if verbose:
            logger.log_error(e)
        elif exit_on_failure:
            logger.log_error(e, quit_program = True)
        return e.returncode
    except Exception as e:
        if verbose:
            logger.log_error(e)
        elif exit_on_failure:
            logger.log_error(e, quit_program = True)
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
    capture_duration = ini.get_ini_integer_value("UserData.Capture", "capture_duration")
    capture_interval = ini.get_ini_integer_value("UserData.Capture", "capture_interval")
    capture_origin_x = ini.get_ini_integer_value("UserData.Capture", "capture_origin_x")
    capture_origin_y = ini.get_ini_integer_value("UserData.Capture", "capture_origin_y")
    capture_resolution_w = ini.get_ini_integer_value("UserData.Capture", "capture_resolution_w")
    capture_resolution_h = ini.get_ini_integer_value("UserData.Capture", "capture_resolution_h")
    capture_framerate = ini.get_ini_integer_value("UserData.Capture", "capture_framerate")
    overwrite_screenshots = ini.get_ini_bool_value("UserData.Capture", "overwrite_screenshots")
    overwrite_videos = ini.get_ini_bool_value("UserData.Capture", "overwrite_videos")

    # Screenshot capturing
    if capture_type == config.CaptureType.SCREENSHOT:

        # Run while capturing screenshots
        if paths.is_path_file(capture_file) and not overwrite_screenshots:
            return run_start()
        else:
            return capture.capture_screenshot_while_running(
                run_func = run_start,
                output_file = capture_file,
                current_win = True,
                capture_origin = (capture_origin_x, capture_origin_y),
                capture_resolution = (capture_resolution_w, capture_resolution_h),
                time_duration = capture_duration,
                time_interval = capture_interval,
                time_units_type = config.UnitType.SECONDS,
                verbose = verbose,
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
                exit_on_failure = exit_on_failure)

    # No capture
    else:
        return run_start()

###########################################################

# Get installer type
def get_installer_type(installer_file):
    with open(installer_file, "r", encoding="utf8", errors="ignore") as file:
        while True:
            file_contents = file.read(2048)
            if not file_contents:
                break
            if "Inno Setup" in file_contents:
                return config.InstallerType.INNO
            if "Nullsoft.NSIS.exehead" in file_contents:
                return config.InstallerType.NSIS
            if "InstallShieldSetup" in file_contents:
                return config.InstallerType.INS
            if "7-Zip" in file_contents:
                return config.InstallerType.SEVENZIP
            if "WinRAR SFX" in file_contents:
                return config.InstallerType.WINRAR
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
    launch_cmd += ["-c", "SET PATH=%PATH%;C:\WINDOWS;"]
    launch_cmd += ["-c", "SET TEMP=C:\WINDOWS\TEMP"]
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
