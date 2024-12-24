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
import programs
import sandbox
import capture
import ini

###########################################################

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
        potential_paths = [os.path.join(search_dir, cmd)]
        for cmd_ext in config.computer_program_extensions:
            potential_paths.append(os.path.join(search_dir, cmd + cmd_ext))
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
        cmd_exts = config.computer_program_extensions)

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

# Command options
class CommandOptions:
    def __init__(
        self,
        cwd = None,
        env = None,
        shell = False,
        is_32_bit = False,
        allow_processing = True,
        force_powershell = False,
        force_appimage = False,
        force_prefix = False,
        is_wine_prefix = False,
        is_sandboxie_prefix = False,
        is_prefix_mapped_cwd = False,
        wine_setup = {},
        sandboxie_setup = {},
        prefix_dir = None,
        prefix_name = None,
        prefix_winver = None,
        prefix_cwd = None,
        lnk_base_path = None,
        output_paths = [],
        blocking_processes = [],
        creationflags = 0,
        stdout = None,
        stderr = None,
        include_stderr = False):

        # Core
        self.cwd = cwd
        if env:
            self.env = env
        else:
            self.env = copy.deepcopy(os.environ)
        self.shell = shell
        self.is_32_bit = is_32_bit

        # Flags
        self.allow_processing = allow_processing
        self.force_powershell = force_powershell
        self.force_appimage = force_appimage
        self.force_prefix = force_prefix

        # Prefix
        self.is_wine_prefix = is_wine_prefix
        self.is_sandboxie_prefix = is_sandboxie_prefix
        self.is_prefix_mapped_cwd = is_prefix_mapped_cwd
        self.wine_setup = wine_setup
        self.sandboxie_setup = sandboxie_setup
        self.prefix_dir = prefix_dir
        self.prefix_name = prefix_name
        self.prefix_winver = prefix_winver
        self.prefix_cwd = prefix_cwd

        # Other
        self.lnk_base_path = lnk_base_path
        self.output_paths = output_paths
        self.blocking_processes = blocking_processes
        self.creationflags = creationflags
        self.stdout = stdout
        self.stderr = stderr
        self.include_stderr = include_stderr

###########################################################

# Setup powershell command
def SetupPowershellCommand(
    cmd,
    options = CommandOptions(),
    verbose = False,
    exit_on_failure = False):

    # Check if powershell command
    if not IsPowershellCommand(cmd) and not options.force_powershell:
        return (cmd, options)

    # Copy params
    new_cmd = cmd
    new_options = copy.deepcopy(options)

    # Setup powershell command
    new_cmd = ["powershell", "-NoProfile", "-Command"]
    new_cmd += CreateCommandList(cmd)
    return (new_cmd, new_options)

# Setup appimage command
def SetupAppImageCommand(
    cmd,
    options = CommandOptions(),
    verbose = False,
    exit_on_failure = False):

    # Check if appimage command
    if not IsAppImageCommand(cmd) and not options.force_appimage:
        return (cmd, options)

    # Copy params
    new_cmd = cmd
    new_options = copy.deepcopy(options)

    # Setup appimage command
    for cmd_segment in CreateCommandList(cmd):
        if cmd_segment.lower().endswith(".appimage"):
            appimage_home_dir = os.path.realpath(cmd_segment + ".home")
            if os.path.exists(appimage_home_dir):
                new_options.env["XDG_CONFIG_HOME"] = os.path.join(appimage_home_dir, ".config")
                new_options.env["XDG_CACHE_HOME"] = os.path.join(appimage_home_dir, ".cache")
                new_options.env["XDG_DATA_HOME"] = os.path.join(appimage_home_dir, ".local", "share")
                new_options.env["XDG_STATE_HOME"] = os.path.join(appimage_home_dir, ".local", "state")
                break
    return (new_cmd, new_options)

# Setup prefix command
def SetupPrefixCommand(
    cmd,
    options = CommandOptions(),
    verbose = False,
    exit_on_failure = False):

    # Check if prefix command
    if not IsPrefixCommand(cmd) and not options.force_prefix:
        return (cmd, options)

    # Copy params
    new_cmd = cmd
    new_options = copy.deepcopy(options)

    # Get default prefix if not specified
    if not new_options.prefix_name or not new_options.prefix_dir:
        new_options.is_wine_prefix = sandbox.ShouldBeRunViaWine(cmd)
        new_options.is_sandboxie_prefix = sandbox.ShouldBeRunViaSandboxie(cmd)
        new_options.prefix_name = config.PrefixType.DEFAULT
        new_options.prefix_dir = sandbox.GetPrefix(
            name = new_options.prefix_name,
            is_wine_prefix = new_options.is_wine_prefix,
            is_sandboxie_prefix = new_options.is_sandboxie_prefix)

    # Create prefix dir if necessary
    if system.IsPathValid(new_options.prefix_dir) and not os.path.exists(new_options.prefix_dir):
        sandbox.CreateBasicPrefix(
            prefix_dir = new_options.prefix_dir,
            prefix_name = new_options.prefix_name,
            prefix_winver = new_options.prefix_winver,
            is_wine_prefix = new_options.is_wine_prefix,
            is_sandboxie_prefix = new_options.is_sandboxie_prefix,
            wine_setup = new_options.wine_setup,
            sandboxie_setup = new_options.sandboxie_setup,
            verbose = verbose,
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
    options = CommandOptions(),
    verbose = False,
    exit_on_failure = False):

    # Preprocess for powershell
    cmd, options = SetupPowershellCommand(
        cmd = cmd,
        options = options,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Preprocess for appimages
    cmd, options = SetupAppImageCommand(
        cmd = cmd,
        options = options,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Preprocess for prefix
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
    options = CommandOptions(),
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
    if isinstance(options.output_paths, list):
        for output_path in options.output_paths:
            sandbox.TransferFromSandbox(
                path = output_path,
                prefix_dir = options.prefix_dir,
                prefix_name = options.prefix_name,
                is_wine_prefix = options.is_wine_prefix,
                is_sandboxie_prefix = options.is_sandboxie_prefix,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

###########################################################

# Print command
def PrintCommand(cmd):
    if isinstance(cmd, str):
        system.Log(cmd)
    if isinstance(cmd, list):
        system.Log(" ".join(cmd))

###########################################################

# Run output command
def RunOutputCommand(
    cmd,
    options = CommandOptions(),
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        cmd = CreateCommandList(cmd)
        if not options:
            options = CommandOptions()
        if not pretend_run:
            if options.allow_processing:
                cmd, options = PreprocessCommand(
                    cmd = cmd,
                    options = options,
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)
            if verbose:
                PrintCommand(cmd)
            if options.shell:
                cmd = CreateCommandString(cmd)
            output = ""
            if options.include_stderr:
                output = subprocess.run(
                    cmd,
                    shell = options.shell,
                    cwd = options.cwd,
                    env = options.env,
                    creationflags = options.creationflags,
                    stdout = subprocess.PIPE,
                    stderr = subprocess.STDOUT).stdout
            else:
                output = subprocess.run(
                    cmd,
                    shell = options.shell,
                    cwd = options.cwd,
                    env = options.env,
                    creationflags = options.creationflags,
                    stdout = subprocess.PIPE).stdout
            if isinstance(options.blocking_processes, list) and len(options.blocking_processes) > 0:
                environment.WaitForNamedProcesses(options.blocking_processes)
            if options.allow_processing:
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
            system.LogErrorAndQuit(e)
        if options.include_stderr:
            return e.output
        return ""
    except Exception as e:
        if verbose:
            system.LogError(e)
        elif exit_on_failure:
            system.LogErrorAndQuit(e)
        return ""

# Run returncode command
def RunReturncodeCommand(
    cmd,
    options = CommandOptions(),
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        cmd = CreateCommandList(cmd)
        if not options:
            options = CommandOptions()
        if not pretend_run:
            if options.allow_processing:
                cmd, options = PreprocessCommand(
                    cmd = cmd,
                    options = options,
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)
            if verbose:
                PrintCommand(cmd)
            if options.shell:
                cmd = CreateCommandString(cmd)
            stdout = options.stdout
            stderr = options.stderr
            if system.IsPathValid(options.stdout):
                stdout = open(options.stdout, "w")
            if system.IsPathValid(options.stderr):
                stderr = open(options.stderr, "w")
            code = subprocess.call(
                cmd,
                shell = options.shell,
                cwd = options.cwd,
                env = options.env,
                creationflags = options.creationflags,
                stdout = stdout,
                stderr = stderr)
            if isinstance(options.blocking_processes, list) and len(options.blocking_processes) > 0:
                environment.WaitForNamedProcesses(options.blocking_processes)
            if system.IsPathValid(options.stdout):
                stdout.close()
            if system.IsPathValid(options.stderr):
                stderr.close()
            if options.allow_processing:
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
            system.LogErrorAndQuit(e)
        return e.returncode
    except Exception as e:
        if verbose:
            system.LogError(e)
        elif exit_on_failure:
            system.LogErrorAndQuit(e)
        return 1

# Run checked command
def RunCheckedCommand(
    cmd,
    options = CommandOptions(),
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
    options = CommandOptions(),
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
    options = CommandOptions(),
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        cmd = CreateCommandList(cmd)
        if not options:
            options = CommandOptions()
        if not pretend_run:
            if options.allow_processing:
                cmd, options = PreprocessCommand(
                    cmd = cmd,
                    options = options,
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)
            if verbose:
                PrintCommand(cmd)
            if options.shell:
                cmd = CreateCommandString(cmd)
            process = subprocess.Popen(
                cmd,
                shell = options.shell,
                cwd = options.cwd,
                env = options.env,
                creationflags = options.creationflags,
                stdout = subprocess.PIPE)
            while True:
                output = CleanCommandOutput(process.stdout.readline().rstrip())
                if output == "" and process.poll() is not None:
                    break
                if output:
                    system.Log(output.strip())
            code = process.poll()
            if isinstance(options.blocking_processes, list) and len(options.blocking_processes) > 0:
                environment.WaitForNamedProcesses(options.blocking_processes)
            if options.allow_processing:
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
            system.LogErrorAndQuit(e)
        return e.returncode
    except Exception as e:
        if verbose:
            system.LogError(e)
        elif exit_on_failure:
            system.LogErrorAndQuit(e)
        return 1

# Run game command
def RunGameCommand(
    game_info,
    cmd,
    options = CommandOptions(),
    capture_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Blocking game start method
    def run_game():
        RunBlockingCommand(
            cmd = cmd,
            options = options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

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

        # Get output file
        output_file = game_info.get_screenshot_asset()

        # Run game while capturing screenshots
        if os.path.exists(output_file) and not overwrite_screenshots:
            run_game()
        else:
            capture.CaptureScreenshotWhileRunning(
                run_func = run_game,
                output_file = output_file,
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

        # Get output file
        output_file = game_info.get_video_asset()

        # Run game while capturing video
        if os.path.exists(output_file) and not overwrite_videos:
            run_game()
        else:
            capture.CaptureVideoWhileRunning(
                run_func = run_game,
                output_file = output_file,
                capture_origin = (capture_origin_x, capture_origin_y),
                capture_resolution = (capture_resolution_w, capture_resolution_h),
                capture_framerate = capture_framerate,
                capture_duration = capture_duration,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

    # No capture
    else:
        run_game()

###########################################################
