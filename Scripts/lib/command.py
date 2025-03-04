# Imports
import os, os.path
import sys
import subprocess
import getpass
import shutil
import copy

# Local imports
import config
import system
import environment
import commandoptions
import programs
import sandbox
import capture
import ini

###########################################################

# Create command options
def CreateCommandOptions(*args, **kwargs):
    return commandoptions.CommandOptions(*args, **kwargs)

# Create command string
def CreateCommandString(cmd):
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
def CreateCommandList(cmd):
    if not cmd:
        return []
    if len(cmd) == 0:
        return []
    if isinstance(cmd, list):
        return copy.deepcopy(cmd)
    if isinstance(cmd, str):
        cmd = cmd.replace(" ", config.token_command_split)
        for quoted_substring in system.SplitByEnclosedSubstrings(cmd, "\"", "\""):
            cmd = cmd.replace(quoted_substring, quoted_substring.replace(config.token_command_split, " "))
        return cmd.split(config.token_command_split)
    return []

###########################################################

# Clean command output
def CleanCommandOutput(output):
    try:
        return output.decode("utf-8", "ignore")
    except:
        return output

###########################################################

# Get starter command
def GetStarterCommand(cmd):
    cmd_list = CreateCommandList(cmd)
    if len(cmd_list) == 0:
        return ""
    return cmd_list[0]

# Check if only starter command
def IsOnlyStarterCommand(cmd):
    cmd_list = CreateCommandList(cmd)
    return len(cmd_list) == 1

###########################################################

# Get runnable command path
def GetRunnableCommandPath(cmd, search_dirs = []):
    for search_dir in search_dirs:
        potential_paths = [system.JoinPaths(search_dir, cmd)]
        for cmd_ext in config.WindowsProgramFileType.cvalues():
            potential_paths.append(system.JoinPaths(search_dir, cmd + cmd_ext))
        for potential_path in potential_paths:
            verified_path = shutil.which(potential_path)
            if verified_path:
                return verified_path
    return shutil.which(cmd)

# Check if runnable command
def IsRunnableCommand(cmd, search_dirs = []):
    cmd_path = GetRunnableCommandPath(cmd, search_dirs)
    if not cmd_path:
        return False
    return True

###########################################################

# Check if command type is found
def IsCommandTypeFound(cmd, cmd_exts = [], search_start = 0, search_len = -1):
    cmd_list = CreateCommandList(cmd)
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
def IsCachedGameCommand(cmd):
    starter_cmd = os.path.normpath(GetStarterCommand(cmd)).lower()
    cached_dir = os.path.normpath(environment.GetCacheGamingRootDir()).lower()
    return starter_cmd.startswith(cached_dir)

# Check if local script command
def IsLocalScriptCommand(cmd):
    starter_cmd = os.path.normpath(GetStarterCommand(cmd)).lower()
    scripts_dir = os.path.normpath(environment.GetScriptsBinDir()).lower()
    return starter_cmd.startswith(scripts_dir)

# Check if local program command
def IsLocalProgramCommand(cmd):
    starter_cmd = GetStarterCommand(cmd)
    is_tool = programs.IsProgramPathTool(starter_cmd)
    is_emulator = programs.IsProgramPathEmulator(starter_cmd)
    return is_tool or is_emulator

# Check if local sandboxed program command
def IsLocalSandboxedProgramCommand(cmd):
    starter_cmd = GetStarterCommand(cmd)
    is_sandboxed_tool = programs.IsProgramPathSandboxedTool(starter_cmd)
    is_sandboxed_emulator = programs.IsProgramPathSandboxedEmulator(starter_cmd)
    return is_sandboxed_tool or is_sandboxed_emulator

# Check if windows executable command
def IsWindowsExecutableCommand(cmd):
    return IsCommandTypeFound(
        cmd = GetStarterCommand(cmd),
        cmd_exts = config.WindowsProgramFileType.cvalues())

# Check if powershell command
def IsPowershellCommand(cmd):
    starter_cmd = os.path.normpath(GetStarterCommand(cmd)).lower()
    return (
        starter_cmd.startswith("powershell") or
        starter_cmd.endswith("powershell") or
        starter_cmd.endswith("powershell.exe")
    )

# Check if appimage command
def IsAppImageCommand(cmd):
    starter_cmd = os.path.normpath(GetStarterCommand(cmd)).lower()
    return starter_cmd.endswith("appimage")

# Check if prefix command
def IsPrefixCommand(cmd):
    return (
        sandbox.ShouldBeRunViaWine(cmd) or
        sandbox.ShouldBeRunViaSandboxie(cmd)
    )

###########################################################

# Setup powershell command
def SetupPowershellCommand(
    cmd,
    options = CreateCommandOptions(),
    verbose = False,
    exit_on_failure = False):

    # Copy params
    new_cmd = cmd
    new_options = options.copy()

    # Setup powershell command
    new_cmd = []
    if not IsPowershellCommand(cmd):
        new_cmd += ["powershell", "-NoProfile", "-Command"]
    new_cmd += CreateCommandList(cmd)
    return (new_cmd, new_options)

# Setup appimage command
def SetupAppImageCommand(
    cmd,
    options = CreateCommandOptions(),
    verbose = False,
    exit_on_failure = False):

    # Copy params
    new_cmd = cmd
    new_options = options.copy()

    # Setup appimage command
    for cmd_segment in CreateCommandList(cmd):
        if cmd_segment.lower().endswith(".appimage"):
            appimage_home_dir = os.path.realpath(cmd_segment + ".home")
            if os.path.exists(appimage_home_dir):
                new_options.set_env_var("XDG_CONFIG_HOME", system.JoinPaths(appimage_home_dir, ".config"))
                new_options.set_env_var("XDG_CACHE_HOME", system.JoinPaths(appimage_home_dir, ".cache"))
                new_options.set_env_var("XDG_DATA_HOME", system.JoinPaths(appimage_home_dir, ".local", "share"))
                new_options.set_env_var("XDG_STATE_HOME", system.JoinPaths(appimage_home_dir, ".local", "state"))
                break
    return (new_cmd, new_options)

# Setup prefix command
def SetupPrefixCommand(
    cmd,
    options = CreateCommandOptions(),
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Copy params
    new_cmd = cmd
    new_options = options.copy()

    # Create prefix if necessary
    if not new_options.has_ready_prefix():
        new_options.create_prefix(
            is_wine_prefix = sandbox.ShouldBeRunViaWine(cmd),
            is_sandboxie_prefix = sandbox.ShouldBeRunViaSandboxie(cmd),
            prefix_name = config.PrefixType.DEFAULT,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Setup prefix command
    new_cmd, new_options = sandbox.SetupPrefixCommand(
        cmd = new_cmd,
        options = new_options,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    new_cmd, new_options = sandbox.SetupPrefixEnvironment(
        cmd = new_cmd,
        options = new_options,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    return (new_cmd, new_options)

###########################################################

# Pre-process command
def PreprocessCommand(
    cmd,
    options = CreateCommandOptions(),
    verbose = False,
    exit_on_failure = False):

    # Preprocess for powershell
    if IsPowershellCommand(cmd) or options.force_powershell():
        cmd, options = SetupPowershellCommand(
            cmd = cmd,
            options = options,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Preprocess for appimages
    if IsAppImageCommand(cmd) or options.force_appimage():
        cmd, options = SetupAppImageCommand(
            cmd = cmd,
            options = options,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Preprocess for prefix
    if IsPrefixCommand(cmd) or options.force_prefix():
        cmd, options = SetupPrefixCommand(
            cmd = cmd,
            options = options,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Return any changes
    return (cmd, options)

# Post-process command
def PostprocessCommand(
    cmd,
    options = CreateCommandOptions(),
    verbose = False,
    exit_on_failure = False):

    # Postprocess for wine
    if sandbox.ShouldBeRunViaWine(cmd):
        sandbox.CleanupWine(
            cmd = cmd,
            options = options,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Postprocess for sandboxie
    if sandbox.ShouldBeRunViaSandboxie(cmd):
        sandbox.CleanupSandboxie(
            cmd = cmd,
            options = options,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Transfer files from sandbox if necessary
    if isinstance(options.get_output_paths(), list):
        for output_path in options.get_output_paths():
            sandbox.TransferFromSandbox(
                path = output_path,
                options = options,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

###########################################################

# Print command
def PrintCommand(cmd):
    if isinstance(cmd, str):
        system.LogInfo(cmd)
    if isinstance(cmd, list):
        system.LogInfo(" ".join(cmd))

###########################################################

# Run output command
def RunOutputCommand(
    cmd,
    options = CreateCommandOptions(),
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        cmd = CreateCommandList(cmd)
        if not options:
            options = CreateCommandOptions()
        if not pretend_run:
            if options.allow_processing():
                cmd, options = PreprocessCommand(
                    cmd = cmd,
                    options = options,
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)
            if verbose:
                PrintCommand(cmd)
            if options.is_shell():
                cmd = CreateCommandString(cmd)
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
            if isinstance(options.get_blocking_processes(), list) and len(options.get_blocking_processes()) > 0:
                environment.WaitForNamedProcesses(options.get_blocking_processes())
            if options.allow_processing():
                PostprocessCommand(
                    cmd = cmd,
                    options = options,
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)
            return CleanCommandOutput(output.strip())
        return ""
    except subprocess.CalledProcessError as e:
        if verbose:
            system.LogError(e)
        elif exit_on_failure:
            system.LogError(e, quit_program = True)
        if options.include_stderr():
            return e.output
        return ""
    except Exception as e:
        if verbose:
            system.LogError(e)
        elif exit_on_failure:
            system.LogError(e, quit_program = True)
        return ""

# Run returncode command
def RunReturncodeCommand(
    cmd,
    options = CreateCommandOptions(),
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        cmd = CreateCommandList(cmd)
        if not options:
            options = CreateCommandOptions()
        if not pretend_run:
            if options.allow_processing():
                cmd, options = PreprocessCommand(
                    cmd = cmd,
                    options = options,
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)
            if verbose:
                PrintCommand(cmd)
            if options.is_shell():
                cmd = CreateCommandString(cmd)
            stdout = options.get_stdout()
            stderr = options.get_stderr()
            if system.IsPathValid(options.get_stdout()):
                stdout = open(options.get_stdout(), "w")
            if system.IsPathValid(options.get_stderr()):
                stderr = open(options.get_stderr(), "w")
            code = subprocess.call(
                cmd,
                shell = options.is_shell(),
                cwd = options.get_cwd(),
                env = options.get_env(),
                creationflags = options.get_creationflags(),
                stdout = stdout,
                stderr = stderr)
            if isinstance(options.get_blocking_processes(), list) and len(options.get_blocking_processes()) > 0:
                environment.WaitForNamedProcesses(options.get_blocking_processes())
            if system.IsPathValid(options.get_stdout()):
                stdout.close()
            if system.IsPathValid(options.get_stderr()):
                stderr.close()
            if options.allow_processing():
                PostprocessCommand(
                    cmd = cmd,
                    options = options,
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)
            return code
        return 0
    except subprocess.CalledProcessError as e:
        if verbose:
            system.LogError(e)
        elif exit_on_failure:
            system.LogError(e, quit_program = True)
        return e.returncode
    except Exception as e:
        if verbose:
            system.LogError(e)
        elif exit_on_failure:
            system.LogError(e, quit_program = True)
        return 1

# Run checked command
def RunCheckedCommand(
    cmd,
    options = CreateCommandOptions(),
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    code = RunReturncodeCommand(
        cmd = cmd,
        options = options,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        system.QuitProgram(code)

# Run exception command
def RunExceptionCommand(
    cmd,
    options = CreateCommandOptions(),
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    code = RunReturncodeCommand(
        cmd = cmd,
        options = options,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        raise ValueError("Unable to run command: %s" % cmd)

# Run blocking command
def RunBlockingCommand(
    cmd,
    options = CreateCommandOptions(),
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        cmd = CreateCommandList(cmd)
        if not options:
            options = CreateCommandOptions()
        if not pretend_run:
            if options.allow_processing():
                cmd, options = PreprocessCommand(
                    cmd = cmd,
                    options = options,
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)
            if verbose:
                PrintCommand(cmd)
            if options.is_shell():
                cmd = CreateCommandString(cmd)
            process = subprocess.Popen(
                cmd,
                shell = options.is_shell(),
                cwd = options.get_cwd(),
                env = options.get_env(),
                creationflags = options.get_creationflags(),
                stdout = subprocess.PIPE)
            while True:
                output = CleanCommandOutput(process.stdout.readline().rstrip())
                if output == "" and process.poll() is not None:
                    break
                if output:
                    system.LogInfo(output.strip())
            code = process.poll()
            if isinstance(options.get_blocking_processes(), list) and len(options.get_blocking_processes()) > 0:
                environment.WaitForNamedProcesses(options.get_blocking_processes())
            if options.allow_processing():
                PostprocessCommand(
                    cmd = cmd,
                    options = options,
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)
            return code
        return 0
    except subprocess.CalledProcessError as e:
        if verbose:
            system.LogError(e)
        elif exit_on_failure:
            system.LogError(e, quit_program = True)
        return e.returncode
    except Exception as e:
        if verbose:
            system.LogError(e)
        elif exit_on_failure:
            system.LogError(e, quit_program = True)
        return 1

# Run capture command
def RunCaptureCommand(
    cmd,
    options = CreateCommandOptions(),
    capture_type = None,
    capture_file = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Blocking start method
    def run_start():
        code = RunBlockingCommand(
            cmd = cmd,
            options = options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return (code == 0)

    # Get capture info
    capture_duration = ini.GetIniIntegerValue("UserData.Capture", "capture_duration")
    capture_interval = ini.GetIniIntegerValue("UserData.Capture", "capture_interval")
    capture_origin_x = ini.GetIniIntegerValue("UserData.Capture", "capture_origin_x")
    capture_origin_y = ini.GetIniIntegerValue("UserData.Capture", "capture_origin_y")
    capture_resolution_w = ini.GetIniIntegerValue("UserData.Capture", "capture_resolution_w")
    capture_resolution_h = ini.GetIniIntegerValue("UserData.Capture", "capture_resolution_h")
    capture_framerate = ini.GetIniIntegerValue("UserData.Capture", "capture_framerate")
    overwrite_screenshots = ini.GetIniBoolValue("UserData.Capture", "overwrite_screenshots")
    overwrite_videos = ini.GetIniBoolValue("UserData.Capture", "overwrite_videos")

    # Screenshot capturing
    if capture_type == config.CaptureType.SCREENSHOT:

        # Run while capturing screenshots
        if system.IsPathFile(capture_file) and not overwrite_screenshots:
            return run_start()
        else:
            return capture.CaptureScreenshotWhileRunning(
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
        if system.IsPathFile(capture_file) and not overwrite_videos:
            return run_start()
        else:
            return capture.CaptureVideoWhileRunning(
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
def GetInstallerType(installer_file):
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
def GetInstallerSetupCommand(
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
def GetDosLaunchCommand(
    options,
    start_program = None,
    start_args = [],
    start_letter = "c",
    start_offset = None,
    fullscreen = False):

    # Search for disc images
    disc_images = system.BuildFileListByExtensions(options.get_prefix_dos_d_drive(), extensions = [".chd"])

    # Create launch command
    launch_cmd = [programs.GetEmulatorProgram("DosBoxX")]

    # Add config file
    launch_cmd += [
        "-conf",
        programs.GetEmulatorPathConfigValue("DosBoxX", "config_file")
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
    if system.IsPathValid(start_offset):
        launch_cmd += ["-c", "cd %s" % start_offset]
    if system.IsPathValid(start_program):
        if isinstance(start_args, list) and len(start_args) > 0:
            launch_cmd += ["-c", "%s %s" % (system.GetFilenameFile(start_program), " ".join(start_args))]
        else:
            launch_cmd += ["-c", "%s" % system.GetFilenameFile(start_program)]

    # Add other flags
    if fullscreen:
        launch_cmd += ["-fullscreen"]

    # Return launch command
    return launch_cmd

# Get win31 launch command
def GetWin31LaunchCommand(
    options,
    start_program = None,
    start_args = [],
    start_letter = "c",
    start_offset = None,
    fullscreen = False):

    # Search for disc images
    disc_images = system.BuildFileListByExtensions(options.get_prefix_dos_d_drive(), extensions = [".chd"])

    # Create launch command
    launch_cmd = [programs.GetEmulatorProgram("DosBoxX")]

    # Add config file
    launch_cmd += [
        "-conf",
        programs.GetEmulatorPathConfigValue("DosBoxX", "config_file_win31")
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
    if system.IsPathValid(start_offset):
        launch_cmd += ["-c", "cd %s" % start_offset]
    if system.IsPathValid(start_program):
        if isinstance(start_args, list) and len(start_args) > 0:
            launch_cmd += ["-c", "WIN RUNEXIT %s %s" % (system.GetFilenameFile(start_program), " ".join(start_args))]
        else:
            launch_cmd += ["-c", "WIN RUNEXIT %s" % system.GetFilenameFile(start_program)]
        launch_cmd += ["-c", "EXIT"]

    # Add other flags
    if fullscreen:
        launch_cmd += ["-fullscreen"]

    # Return launch command
    return launch_cmd

# Get scumm launch command
def GetScummLaunchCommand(
    options,
    fullscreen = False):

    # Create launch command
    launch_cmd = [programs.GetEmulatorProgram("ScummVM")]
    launch_cmd += [
        "--path=%s" % system.JoinPaths(options.get_prefix_c_drive_real(), config.computer_folder_scumm)
    ]
    launch_cmd += ["--auto-detect"]
    launch_cmd += [
        "--savepath=%s" % system.JoinPaths(options.get_prefix_user_profile_dir(), config.computer_folder_gamedata)
    ]
    if fullscreen:
        launch_cmd += ["--fullscreen"]

    # Return launch command
    return launch_cmd

###########################################################
