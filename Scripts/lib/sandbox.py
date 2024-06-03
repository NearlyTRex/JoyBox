# Imports
import os, os.path
import ntpath
import sys
import getpass
import copy

# Local imports
import config
import system
import environment
import command
import programs
import registry
import gui
import ini
from tools import dxvk
from tools import vkd3d

###########################################################

# Check if command should be run via wine
def ShouldBeRunViaWine(cmd):

    # Check platform
    if not environment.IsWinePlatform():
        return False

    # Already using wine
    if command.GetStarterCommand(cmd) == GetWineCommand():
        return False

    # Wine runs windows executable formats only
    if not command.IsWindowsExecutableCommand(cmd):
        return False

    # Cached game commands or sandboxed local programs should use wine
    is_cached_game_cmd = command.IsCachedGameCommand(cmd)
    is_sandboxed_program_cmd = command.IsLocalSandboxedProgramCommand(cmd)
    return (
        is_cached_game_cmd or
        is_sandboxed_program_cmd
    )

# Check if command should be run via sandboxie
def ShouldBeRunViaSandboxie(cmd):

    # Check platform
    if not environment.IsSandboxiePlatform():
        return False

    # Already using sandboxie
    if command.GetStarterCommand(cmd) == GetSandboxieCommand():
        return False

    # Sandboxie runs windows executable formats only
    if not command.IsWindowsExecutableCommand(cmd):
        return False

    # Cached game commands or sandboxed local programs should use sandboxie
    is_cached_game_cmd = command.IsCachedGameCommand(cmd)
    is_sandboxed_program_cmd = command.IsLocalSandboxedProgramCommand(cmd)
    return (
        is_cached_game_cmd or
        is_sandboxed_program_cmd
    )

###########################################################

# Get wine command
def GetWineCommand():
    return programs.GetToolProgram("Wine")

# Get sandboxie command
def GetSandboxieCommand():
    return programs.GetToolProgram("Sandboxie")

###########################################################

# Get wine blocking processes
def GetWineBlockingProcesses():
    return [
        programs.GetToolProgram("WineServer")
    ]

# Get sandboxie blocking processes
def GetSandboxieBlockingProcesses():
    return [
        programs.GetToolProgram("Sandboxie"),
        programs.GetToolProgram("SandboxieIni"),
        programs.GetToolProgram("SandboxieRpcss"),
        programs.GetToolProgram("SandboxieDcomlaunch")
    ]

# Get blocking processes
def GetBlockingProcesses(initial_processes = [], is_wine_prefix = False, is_sandboxie_prefix = False):
    blocking_processes = copy.deepcopy(initial_processes)
    if is_wine_prefix:
        blocking_processes += GetWineBlockingProcesses()
    elif is_sandboxie_prefix:
        blocking_processes += GetSandboxieBlockingProcesses()
    return blocking_processes

###########################################################

# Get wine prefix
def GetWinePrefix(name):
    return os.path.join(programs.GetToolPathConfigValue("Wine", "sandbox_dir"), name)

# Get sandboxie prefix
def GetSandboxiePrefix(name):
    return os.path.join(programs.GetToolPathConfigValue("Sandboxie", "sandbox_dir"), name)

# Get prefix
def GetPrefix(name, is_wine_prefix = False, is_sandboxie_prefix = False):
    prefix_dir = None
    if name:
        if is_wine_prefix:
            prefix_dir = GetWinePrefix(name)
        elif is_sandboxie_prefix:
            prefix_dir = GetSandboxiePrefix(name)
    return prefix_dir

###########################################################

# Get wine real drive path
def GetWineRealDrivePath(prefix_dir, drive):
    if drive.lower() == "c":
        return os.path.join(prefix_dir, "drive_c")
    else:
        return os.path.join(prefix_dir, "dosdevices", drive.lower() + ":")

# Get sandboxie real drive path
def GetSandboxieRealDrivePath(prefix_dir, drive):
    return os.path.join(prefix_dir, "drive", drive.upper())

# Get real drive path
def GetRealDrivePath(prefix_dir, drive, is_wine_prefix = False, is_sandboxie_prefix = False):
    real_drive_path = None
    if is_wine_prefix:
        real_drive_path = GetWineRealDrivePath(prefix_dir, drive)
    elif is_sandboxie_prefix:
        real_drive_path = GetSandboxieRealDrivePath(prefix_dir, drive)
    return real_drive_path

###########################################################

# Get wine user profile path
def GetWineUserProfilePath(prefix_dir):
    return system.NormalizeFilePath(os.path.join(prefix_dir, "drive_c", "users", getpass.getuser()))

# Get sandboxie user profile path
def GetSandboxieUserProfilePath(prefix_dir):
    return system.NormalizeFilePath(os.path.join(prefix_dir, "user", "current"))

# Get user profile path
def GetUserProfilePath(prefix_dir, is_wine_prefix = False, is_sandboxie_prefix = False):
    user_profile_dir = None
    if is_wine_prefix:
        user_profile_dir = GetWineUserProfilePath(prefix_dir)
    elif is_sandboxie_prefix:
        user_profile_dir = GetSandboxieUserProfilePath(prefix_dir)
    return user_profile_dir

###########################################################

# Get wine public profile path
def GetWinePublicProfilePath(prefix_dir):
    return system.NormalizeFilePath(os.path.join(prefix_dir, "drive_c", "users", "Public"))

# Get sandboxie public profile path
def GetSandboxiePublicProfilePath(prefix_dir):
    return system.NormalizeFilePath(os.path.join(prefix_dir, "drive", "C", "Public"))

# Get public profile path
def GetPublicProfilePath(prefix_dir, is_wine_prefix = False, is_sandboxie_prefix = False):
    public_profile_dir = None
    if is_wine_prefix:
        public_profile_dir = GetWinePublicProfilePath(prefix_dir)
    elif is_sandboxie_prefix:
        public_profile_dir = GetSandboxiePublicProfilePath(prefix_dir)
    return public_profile_dir

###########################################################

# Get Goldberg SteamEmu base path
def GetGoldbergSteamEmuBasePath(prefix_dir):
    return os.path.join(prefix_dir, "AppData", "Roaming", "Goldberg SteamEmu Saves")

# Get Goldberg SteamEmu username file
def GetGoldbergSteamEmuUserNameFile(prefix_dir):
    return os.path.join(GetGoldbergSteamEmuBasePath(prefix_dir), "settings", "account_name.txt")

# Get Goldberg SteamEmu userid file
def GetGoldbergSteamEmuUserIDFile(prefix_dir):
    return os.path.join(GetGoldbergSteamEmuBasePath(prefix_dir), "settings", "user_steam_id.txt")

###########################################################

# Install wine dlls
def InstallWineDlls(
    prefix_dir,
    dlls_32 = [],
    dlls_64 = [],
    is_32_bit = False,
    verbose = False,
    exit_on_failure = False):
    wine_c_drive = GetWineRealDrivePath(prefix_dir, "c")
    wine_system32_dir = os.path.join(wine_c_drive, "windows", "system32")
    wine_syswow64_dir = os.path.join(wine_c_drive, "windows", "syswow64")
    if is_32_bit:
        for lib32 in dlls_32:
            system.CopyFileOrDirectory(
                src = lib32,
                dest = wine_system32_dir,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
    else:
        for lib64 in dlls_64:
            system.CopyFileOrDirectory(
                src = lib64,
                dest = os.path.join(wine_c_drive, "windows", "system32"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
        for lib32 in dlls_32:
            system.CopyFileOrDirectory(
                src = lib32,
                dest = wine_syswow64_dir,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

# Install sandboxie dlls
def InstallSandboxieDlls(
    prefix_dir,
    dlls_32 = [],
    dlls_64 = [],
    is_32_bit = False,
    verbose = False,
    exit_on_failure = False):
    pass

# Install dlls
def InstallDlls(
    prefix_dir,
    dlls_32 = [],
    dlls_64 = [],
    is_32_bit = False,
    is_wine_prefix = False,
    is_sandboxie_prefix = False,
    verbose = False,
    exit_on_failure = False):
    if is_wine_prefix:
        InstallWineDlls(
            prefix_dir = prefix_dir,
            dlls_32 = dlls_32,
            dlls_64 = dlls_64,
            is_32_bit = is_32_bit,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
    elif is_sandboxie_prefix:
        InstallSandboxieDlls(
            prefix_dir = prefix_dir,
            dlls_32 = dlls_32,
            dlls_64 = dlls_64,
            is_32_bit = is_32_bit,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

###########################################################

# Restore registry
def RestoreRegistry(
    prefix_dir,
    prefix_name,
    is_wine_prefix = False,
    is_sandboxie_prefix = False,
    verbose = False,
    exit_on_failure = False):

    # Get user profile
    user_profile_dir = GetUserProfilePath(
        prefix_dir = prefix_dir,
        is_wine_prefix = is_wine_prefix,
        is_sandboxie_prefix = is_sandboxie_prefix)
    if not user_profile_dir:
        return False

    # Get registry dir
    registry_dir = os.path.join(user_profile_dir, config.computer_registry_folder)

    # Get registry file
    registry_file = ""
    if prefix_name == config.prefix_type_setup:
        registry_file = os.path.join(registry_dir, config.registry_filename_setup)
    elif prefix_name == config.prefix_type_game:
        registry_file = os.path.join(registry_dir, config.registry_filename_game)
    if not os.path.exists(registry_file):
        return True

    # Import registry file
    return registry.ImportRegistryFile(
        registry_file = registry_file,
        prefix_dir = prefix_dir,
        prefix_name = prefix_name,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

# Backup registry
def BackupRegistry(
    prefix_dir,
    prefix_name,
    registry_keys = [],
    is_wine_prefix = False,
    is_sandboxie_prefix = False,
    verbose = False,
    exit_on_failure = False):

    # Ignore empty keys
    if len(registry_keys) == 0:
        return True

    # Get user profile
    user_profile_dir = GetUserProfilePath(
        prefix_dir = prefix_dir,
        is_wine_prefix = is_wine_prefix,
        is_sandboxie_prefix = is_sandboxie_prefix)
    if not user_profile_dir:
        return False

    # Get registry dir
    registry_dir = os.path.join(user_profile_dir, config.computer_registry_folder)

    # Get registry file
    registry_file = ""
    if prefix_name == config.prefix_type_setup:
        registry_file = os.path.join(registry_dir, config.registry_filename_setup)
    elif prefix_name == config.prefix_type_game:
        registry_file = os.path.join(registry_dir, config.registry_filename_game)

    # Get registry export keys
    registry_export_keys = []
    if prefix_name == config.prefix_type_setup:
        registry_export_keys = config.registry_export_keys_setup
    elif prefix_name == config.prefix_type_game:
        registry_export_keys = config.registry_export_keys_game

    # Get registry ignore keys
    registry_ignore_keys = []
    if prefix_name == config.prefix_type_setup:
        registry_ignore_keys = config.ignored_registry_keys_setup
    elif prefix_name == config.prefix_type_game:
        registry_ignore_keys = config.ignored_registry_keys_game

    # Backup registry
    return registry.BackupUserRegistry(
        registry_file = registry_file,
        prefix_dir = prefix_dir,
        prefix_name = prefix_name,
        export_keys = registry_export_keys,
        ignore_keys = registry_ignore_keys,
        keep_keys = registry_keys,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

###########################################################

# Find first available real drive path
def FindFirstAvailableRealDrivePath(prefix_dir, is_wine_prefix = False, is_sandboxie_prefix = False):

    # Check params
    system.AssertPathExists(prefix_dir, "prefix_dir")

    # Only go through potentially available drives
    for letter in config.drives_regular:

        # Get drive path and check if its available
        drive_path = GetRealDrivePath(
            prefix_dir = prefix_dir,
            drive = letter,
            is_wine_prefix = is_wine_prefix,
            is_sandboxie_prefix = is_sandboxie_prefix)
        if not os.path.exists(drive_path):
            return drive_path

    # Nothing available
    return None

# Mount directory to available drive
def MountDirectoryToAvailableDrive(
    source_dir,
    prefix_dir,
    is_wine_prefix = False,
    is_sandboxie_prefix = False,
    verbose = False,
    exit_on_failure = False):

    # Check params
    system.AssertPathExists(source_dir, "source_dir")
    system.AssertPathExists(prefix_dir, "prefix_dir")

    # Get first available drive path
    drive_path = FindFirstAvailableRealDrivePath(
        prefix_dir,
        is_wine_prefix = is_wine_prefix,
        is_sandboxie_prefix = is_sandboxie_prefix)
    if not system.IsPathValid(drive_path):
        return False

    # Create symlink
    return system.CreateSymlink(
        src = source_dir,
        dest = drive_path,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

# Unmount all mounted drives
def UnmountAllMountedDrives(
    prefix_dir,
    is_wine_prefix = False,
    is_sandboxie_prefix = False,
    verbose = False,
    exit_on_failure = False):

    # Check params
    system.AssertPathExists(prefix_dir, "prefix_dir")

    # Only go through potentially available drives
    for letter in config.drives_regular:

        # Get real drive path
        drive_path = GetRealDrivePath(
            prefix_dir = prefix_dir,
            drive = letter,
            is_wine_prefix = is_wine_prefix,
            is_sandboxie_prefix = is_sandboxie_prefix)

        # Remove symlink
        system.RemoveSymlink(
            symlink = drive_path,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

###########################################################

# Get prefix path info
def GetPrefixPathInfo(
    path,
    prefix_dir,
    is_virtual_path = False,
    is_real_path = False,
    is_wine_prefix = False,
    is_sandboxie_prefix = False):

    # Check path
    if not system.IsPathValid(path):
        return None

    # Check prefix
    if not system.IsPathValid(prefix_dir):
        return None

    # These are some potential types of paths
    # - /home/user/.wine/drive_c/foo/bar
    # - /home/user/.wine/dosdevices/c:/foo/bar
    # - C:/Sandboxie/Sandbox/Default/drives/C/foo/bar
    # - C:/foo/bar

    # Normalize paths
    path = system.NormalizeFilePath(path, separator = config.os_pathsep)
    prefix_dir = system.NormalizeFilePath(prefix_dir, separator = config.os_pathsep)

    # Fix path inconsistencies
    if is_wine_prefix:
        if is_virtual_path and path.startswith(config.drive_root_posix):
            is_virtual_path = False
            is_real_path = True

    # Initialize letter, offset, and base
    path_drive_letter = ""
    path_drive_offset = ""
    path_drive_extra = ""
    path_drive_base = ""

    # Path starts with prefix
    if path.startswith(prefix_dir):

        # Find drive letter and offset
        if is_virtual_path:
            path_drive_letter = system.GetDirectoryDrive(path)
            path_drive_offset = path[len(system.GetDirectoryAnchor(path)):]
        elif is_real_path:
            path_drive_start = path[len(prefix_dir + config.os_pathsep):]
            if is_wine_prefix:
                if path_drive_start.startswith("drive_c"):
                    path_drive_letter = "c"
                    path_drive_offset = path_drive_start[len("drive_c" + config.os_pathsep):]
                elif path_drive_start.startswith("dosdevices"):
                    path_drive_start = path_drive_start[len("dosdevices" + config.os_pathsep):]
                    path_drive_token = ""
                    for path_token in path_drive_start.split(config.os_pathsep):
                        path_drive_token = path_token
                        break
                    if len(path_drive_token) > 0:
                        path_drive_letter = path_drive_token[0].lower()
                        path_drive_offset = path_drive_start[len(path_drive_token + config.os_pathsep):]
            elif is_sandboxie_prefix:
                if path_drive_start.startswith("drives"):
                    path_drive_start = path_drive_start[len("drives" + config.os_pathsep):]
                    path_drive_token = ""
                    for path_token in path_drive_start.split(config.os_pathsep):
                        path_drive_token = path_token
                        break
                    if len(path_drive_token) > 0:
                        path_drive_letter = path_drive_token.lower()
                        path_drive_offset = path_drive_start[len(path_drive_token + config.os_pathsep):]

        # Find drive base
        if is_virtual_path:
            if is_wine_prefix:
                path_drive_base = os.path.join(prefix_dir, "dosdevices", path_drive_letter.lower() + ":")
            elif is_sandboxie_prefix:
                path_drive_base = os.path.join(prefix_dir, "drives", path_drive_letter.upper())
        elif is_real_path:
            path_drive_base = path[-len(path_drive_offset):]

    # Prefix and path are not related
    else:

        # Wine
        if is_wine_prefix:
            if is_virtual_path:
                path_drive_letter = system.GetDirectoryDrive(path)
            else:
                path_drive_letter = "z"
            path_drive_offset = path[len(system.GetDirectoryAnchor(path)):]
            path_drive_base = GetWineRealDrivePath(prefix_dir, path_drive_letter)

        # Sandboxie
        elif is_sandboxie_prefix:
            path_drive_letter = system.GetDirectoryDrive(path)
            path_drive_offset = path[len(system.GetDirectoryAnchor(path)):]
            path_drive_extra = system.NormalizeFilePath(os.path.join("Users", getpass.getuser()), separator = config.os_pathsep)
            if path_drive_offset.startswith(path_drive_extra):
                path_drive_base = GetSandboxieUserProfilePath(prefix_dir)
                path_drive_offset = path_drive_offset[len(path_drive_extra + config.os_pathsep):]
            else:
                path_drive_base = GetSandboxieRealDrivePath(prefix_dir, path_drive_letter)

        # Neither
        else:
            path_drive_offset = path[len(system.GetDirectoryAnchor(path)):]
            path_drive_base = system.GetDirectoryDrive(path)
            if environment.IsWinePlatform():
                path_drive_letter = "z"
            else:
                path_drive_letter = system.GetDirectoryDrive(path)
            is_virtual_path = False
            is_real_path = True

    # Construct full virtual and real paths
    path_full_virtual = ""
    path_full_real = ""
    if is_virtual_path:
        path_full_virtual = path
        path_full_real = os.path.join(path_drive_base, path_drive_offset)
    elif is_real_path:
        path_full_virtual += path_drive_letter.upper() + ":" + config.os_pathsep
        path_full_virtual += path_drive_extra + config.os_pathsep
        path_full_virtual += path_drive_offset
        path_full_real = path

    # Check for consistency
    if is_virtual_path:
        system.AssertCondition(
            condition = (path == path_full_virtual),
            description = "Original virtual path must match constructed virtual path")
    elif is_real_path:
        system.AssertCondition(
            condition = (path == path_full_real),
            description = "Original real path must match constructed real path")

    # Return path info
    info = {}
    info["path"] = system.NormalizeFilePath(path)
    info["prefix"] = system.NormalizeFilePath(prefix_dir)
    info["is_virtual"] = is_virtual_path
    info["is_real"] = is_real_path
    info["is_wine"] = is_wine_prefix
    info["is_sandboxie"] = is_sandboxie_prefix
    info["letter"] = path_drive_letter
    info["base"] = system.NormalizeFilePath(path_drive_base)
    info["offset"] = system.NormalizeFilePath(path_drive_offset)
    if len(path_drive_extra):
        info["extra"] = system.NormalizeFilePath(path_drive_extra)
    else:
        info["extra"] = path_drive_extra
    info["real"] = system.NormalizeFilePath(path_full_real)
    info["virtual"] = system.NormalizeFilePath(path_full_virtual, force_windows = True)
    return info

# Get prefix sync objects
def GetPrefixSyncObjs(
    prefix_dir,
    general_prefix_dir,
    is_wine_prefix = False,
    is_sandboxie_prefix = False,
    user_data_sync_basedir = None,
    user_data_sync_objs = []):

    # Create sync objs
    sync_objs = []

    # Get user profile directory
    user_profile_dir = GetUserProfilePath(
        prefix_dir = prefix_dir,
        is_wine_prefix = is_wine_prefix,
        is_sandboxie_prefix = is_sandboxie_prefix)

    # Add user data mapping
    if general_prefix_dir and user_data_sync_basedir:
        for sync_obj in user_data_sync_objs:
            sync_entry = {}
            sync_entry["stored"] = os.path.join(general_prefix_dir, config.computer_game_data_folder, sync_obj)
            sync_entry["live"] = os.path.join(user_data_sync_basedir, sync_obj)
            sync_objs.append(sync_entry)

    # Add user profile mapping
    if general_prefix_dir and user_profile_dir:
        if is_sandboxie_prefix:
            for sync_dir in config.computer_user_folders_builtin:
                sync_entry = {}
                sync_entry["stored"] = os.path.join(general_prefix_dir, sync_dir)
                sync_entry["live"] = os.path.join(user_profile_dir, sync_dir)
                sync_objs.append(sync_entry)

    # Return sync objs
    return sync_objs

###########################################################

# Setup prefix environment
def SetupPrefixEnvironment(
    cmd,
    options = None,
    verbose = False,
    exit_on_failure = False):

    # Check options
    if not options:
        options = command.CommandOptions()

    # Ignore non-prefix environments
    if not options.is_wine_prefix and not options.is_sandboxie_prefix:
        return (cmd, options)

    # Copy params
    new_cmd = cmd
    new_options = copy.deepcopy(options)

    # Modify for wine
    if new_options.is_wine_prefix:

        # Get wine setup
        wine_setup_overrides = {}
        wine_setup_use_dxvk = False
        wine_setup_use_vkd3d = False
        if config.json_key_sandbox_wine_overrides in new_options.wine_setup:
            wine_setup_overrides = new_options.wine_setup[config.json_key_sandbox_wine_overrides]
        if config.json_key_sandbox_wine_use_dxvk in new_options.wine_setup:
            wine_setup_use_dxvk = new_options.wine_setup[config.json_key_sandbox_wine_use_dxvk]
        if config.json_key_sandbox_wine_use_vkd3d in new_options.wine_setup:
            wine_setup_use_vkd3d = new_options.wine_setup[config.json_key_sandbox_wine_use_vkd3d]

        # Set dxvk options
        if wine_setup_use_dxvk:
            new_options.env["DXVK_HUD"] = "0"

        # Improve performance by not showing everything
        # To show only errors, change to fixme-all
        new_options.env["WINEDEBUG"] = "-all"

        # Set prefix location
        if system.IsPathValid(new_options.prefix_dir):
            new_options.env["WINEPREFIX"] = new_options.prefix_dir

        # Set prefix bitness
        if new_options.is_32_bit:
            new_options.env["WINEARCH"] = "win32"
        else:
            new_options.env["WINEARCH"] = "win64"

        # Set prefix overrides
        wine_overrides = ["winemenubuilder.exe=d"]
        if new_options.prefix_name and new_options.prefix_name.lower() in wine_setup_overrides:
            wine_overrides += wine_setup_overrides[new_options.prefix_name.lower()]
        new_options.env["WINEDLLOVERRIDES"] = ";".join(wine_overrides)

        # Map the current working directory to the prefix
        if new_options.is_prefix_mapped_cwd and system.IsPathValid(new_options.cwd):
            cwd_drive = GetRealDrivePath(
                prefix_dir = new_options.prefix_dir,
                drive = config.drive_prefix_cwd,
                is_wine_prefix = new_options.is_wine_prefix,
                is_sandboxie_prefix = new_options.is_sandboxie_prefix)
            if system.IsPathValid(cwd_drive):
                system.RemoveSymlink(
                    symlink = cwd_drive,
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)
                system.CreateSymlink(
                    src = new_options.cwd,
                    dest = cwd_drive,
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)

    # Modify for sandboxie
    elif new_options.is_sandboxie_prefix:
        pass

    # Return results
    return (new_cmd, new_options)

# Setup prefix command
def SetupPrefixCommand(
    cmd,
    options = None,
    verbose = False,
    exit_on_failure = False):

    # Check options
    if not options:
        options = command.CommandOptions()

    # Ignore non-prefix commands
    if not options.is_wine_prefix and not options.is_sandboxie_prefix:
        return (cmd, options)

    # Get original command info
    orig_cmd_starter = command.GetStarterCommand(cmd)
    orig_cmd_list = command.CreateCommandList(cmd)
    if len(orig_cmd_list) == 0:
        return (cmd, options)

    # Copy params
    new_cmd = []
    new_options = copy.deepcopy(options)

    # Create command
    if options.is_wine_prefix:
        new_cmd = [GetWineCommand()]
    elif options.is_sandboxie_prefix:
        new_cmd = [
            GetSandboxieCommand(),
            "/box:%s" % options.prefix_name
        ]
        if options.prefix_name == config.prefix_type_tool:
            new_cmd += ["/hide_window"]

    # Modify for wine
    if new_options.is_wine_prefix:

        # Get wine setup
        wine_setup_desktop = ""
        wine_setup_use_virtual_desktop = False
        if config.json_key_sandbox_wine_desktop in new_options.wine_setup:
            wine_setup_desktop = new_options.wine_setup[config.json_key_sandbox_wine_desktop]
        if config.json_key_sandbox_wine_use_virtual_desktop in new_options.wine_setup:
            wine_setup_use_virtual_desktop = new_options.wine_setup[config.json_key_sandbox_wine_use_virtual_desktop]

        # Set desktop options
        if wine_setup_use_virtual_desktop:
            if len(wine_setup_desktop):
                new_cmd += ["explorer", "/desktop=" + wine_setup_desktop]
            else:
                desktop_width = ini.GetIniValue("UserData.Resolution", "screen_resolution_w")
                desktop_height = ini.GetIniValue("UserData.Resolution", "screen_resolution_h")
                new_cmd += ["explorer", "/desktop=%sx%s" % (desktop_width, desktop_height)]

    # Adjust command based on executable type
    if orig_cmd_starter.endswith(".lnk"):
        info = system.GetLinkInfo(
            lnk_path = orig_cmd_starter,
            lnk_base_path = options.lnk_base_path)
        has_valid_target = os.path.exists(info["target"])
        has_valid_cwd = os.path.exists(info["cwd"])
        if not has_valid_target or not has_valid_cwd:
            gui.DisplayErrorPopup(
                title_text = "Unable to resolve LNK file",
                message_text = "Unable to resolve LNK file %s to an actual target" % orig_cmd_starter)
        new_cmd += [info["target"]]
        new_cmd += info["args"]
        new_options.cwd = info["cwd"]
    elif orig_cmd_starter.endswith(".bat"):
        if options.is_sandboxie_prefix:
            new_cmd += ["cmd", "/c"]
        new_cmd += orig_cmd_list
    else:
        new_cmd += orig_cmd_list

    # Override cwd if requested for this prefix
    prefix_c_drive = GetRealDrivePath(
        prefix_dir = new_options.prefix_dir,
        drive = "c",
        is_wine_prefix = new_options.is_wine_prefix,
        is_sandboxie_prefix = new_options.is_sandboxie_prefix)
    if prefix_c_drive and new_options.prefix_cwd and len(new_options.prefix_cwd):
        new_options.cwd = os.path.realpath(os.path.join(prefix_c_drive, new_options.prefix_cwd))

    # Return results
    return (new_cmd, new_options)

###########################################################

# Cleanup wine
def CleanupWine(cmd, options, verbose = False, exit_on_failure = False):

    # Get wine server tool
    wine_server_tool = programs.GetToolProgram("WineServer")

    # Kill processes running under wine
    command.RunBlockingCommand(
        cmd = [wine_server_tool, "-k"],
        options = command.CommandOptions(
            shell = True),
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Kill wine itself
    environment.KillActiveNamedProcesses([wine_server_tool])

# Cleanup sandboxie
def CleanupSandboxie(cmd, options, verbose = False, exit_on_failure = False):
    pass

###########################################################

# Create wine prefix
def CreateWinePrefix(
    prefix_dir,
    prefix_name,
    prefix_winver,
    wine_setup = {},
    is_32_bit = False,
    verbose = False,
    exit_on_failure = False):

    # Make directory
    system.MakeDirectory(prefix_dir, verbose = verbose, exit_on_failure = exit_on_failure)

    # Get wine boot tool
    wine_boot_tool = programs.GetToolProgram("WineBoot")

    # Get wine tricks tool
    wine_tricks_tool = programs.GetToolProgram("WineTricks")

    # Get wine setup
    wine_setup_tricks = {}
    wine_setup_use_dxvk = False
    wine_setup_use_vkd3d = False
    if config.json_key_sandbox_wine_tricks in wine_setup:
        wine_setup_tricks = wine_setup[config.json_key_sandbox_wine_tricks]
    if config.json_key_sandbox_wine_use_dxvk in wine_setup:
        wine_setup_use_dxvk = wine_setup[config.json_key_sandbox_wine_use_dxvk]
    if config.json_key_sandbox_wine_use_vkd3d in wine_setup:
        wine_setup_use_vkd3d = wine_setup[config.json_key_sandbox_wine_use_vkd3d]

    # Get list of winetricks
    winetricks = []
    if prefix_winver and isinstance(prefix_winver, str) and len(prefix_winver):
        winetricks += [prefix_winver]
    if prefix_name and prefix_name.lower() in wine_setup_tricks:
        winetricks += wine_setup_tricks[prefix_name.lower()]

    # Initialize prefix
    cmds_to_run = []
    cmds_to_run.append([wine_boot_tool])
    if len(winetricks):
        cmds_to_run.append([wine_tricks_tool] + winetricks)
    for cmd in cmds_to_run:
        options = command.CommandOptions(
            is_wine_prefix = True,
            is_32_bit = is_32_bit,
            prefix_dir = prefix_dir,
            prefix_name = prefix_name,
            prefix_winver = prefix_winver,
            blocking_processes = [command.GetStarterCommand(cmd)])
        cmd, options = SetupPrefixEnvironment(
            cmd = cmd,
            options = options,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        command.RunBlockingCommand(
            cmd = cmd,
            options = options,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Copy dxvk libraries
    if wine_setup_use_dxvk:
        InstallWineDlls(
            prefix_dir = prefix_dir,
            dlls_32 = dxvk.GetLibs32(),
            dlls_64 = dxvk.GetLibs64(),
            is_32_bit = is_32_bit)

    # Copy vkd3d libraries
    if wine_setup_use_vkd3d:
        InstallWineDlls(
            prefix_dir = prefix_dir,
            dlls_32 = vkd3d.GetLibs32(),
            dlls_64 = vkd3d.GetLibs64(),
            is_32_bit = is_32_bit)

    # Creation successful
    return True

# Create sandboxie prefix
def CreateSandboxiePrefix(
    prefix_dir,
    prefix_name,
    prefix_winver,
    sandboxie_setup = {},
    is_32_bit = False,
    verbose = False,
    exit_on_failure = False):

    # Make directories
    system.MakeDirectory(prefix_dir, verbose = verbose, exit_on_failure = exit_on_failure)
    system.MakeDirectory(GetSandboxieRealDrivePath(prefix_dir, "C"), verbose = verbose, exit_on_failure = exit_on_failure)
    system.MakeDirectory(GetSandboxieUserProfilePath(prefix_dir), verbose = verbose, exit_on_failure = exit_on_failure)

    # Get sandboxie ini tool
    sandboxie_ini_tool = programs.GetToolProgram("SandboxieIni")

    # Set sandboxie param
    def SetSandboxieBoxParam(sandbox_name, sandbox_param, sandbox_value):
        cmd = [sandboxie_ini_tool, "set", sandbox_name, sandbox_param, sandbox_value]
        options = command.CommandOptions(
            is_sandboxie_prefix = True,
            prefix_dir = prefix_dir,
            prefix_name = prefix_name,
            blocking_processes = [sandboxie_ini_tool],
            shell = True)
        cmd, options = SetupPrefixEnvironment(
            cmd = cmd,
            options = options,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        command.RunBlockingCommand(
            cmd = cmd,
            options = options,
            verbose = verbose)

    # Initialize prefix
    SetSandboxieBoxParam(prefix_name, "Enabled", "y")
    SetSandboxieBoxParam(prefix_name, "FileRootPath", prefix_dir)
    SetSandboxieBoxParam(prefix_name, "BlockNetParam", "n")
    SetSandboxieBoxParam(prefix_name, "BlockNetworkFiles", "y")
    SetSandboxieBoxParam(prefix_name, "RecoverFolder", "%Desktop%")
    SetSandboxieBoxParam(prefix_name, "BorderColor", "#00ffff,off,6")
    SetSandboxieBoxParam(prefix_name, "ConfigLevel", "10")
    SetSandboxieBoxParam(prefix_name, "BoxNameTitle", "-")
    SetSandboxieBoxParam(prefix_name, "CopyLimitKb", "-1")
    SetSandboxieBoxParam(prefix_name, "NoSecurityIsolation", "y")
    SetSandboxieBoxParam(prefix_name, "Template", "OpenBluetooth")

    # Creation successful
    return True

# Create basic prefix
def CreateBasicPrefix(
    prefix_dir,
    prefix_name,
    prefix_winver = None,
    clean_existing = True,
    is_wine_prefix = False,
    is_sandboxie_prefix = False,
    wine_setup = {},
    sandboxie_setup = {},
    is_32_bit = False,
    verbose = False,
    exit_on_failure = False):

    # Check prefix
    if not system.IsPathValid(prefix_dir):
        return False

    # Clean prefix
    if clean_existing:
        system.RemoveObject(prefix_dir, verbose = verbose, exit_on_failure = False)

    # Setup wine prefix
    if is_wine_prefix:

        # Create wine prefix
        CreateWinePrefix(
            prefix_dir = prefix_dir,
            prefix_name = prefix_name,
            prefix_winver = prefix_winver,
            wine_setup = wine_setup,
            is_32_bit = is_32_bit,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Replace symlinked directories
        system.ReplaceSymlinkedDirectories(
            dir = GetWineUserProfilePath(prefix_dir),
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Setup sandboxie prefix
    elif is_sandboxie_prefix:

        # Create sandboxie prefix
        CreateSandboxiePrefix(
            prefix_dir = prefix_dir,
            prefix_name = prefix_name,
            prefix_winver = prefix_winver,
            sandboxie_setup = sandboxie_setup,
            is_32_bit = is_32_bit,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Check result
    return system.IsPathValid(prefix_dir)

# Create linked prefix
def CreateLinkedPrefix(
    prefix_dir,
    prefix_name,
    prefix_winver = None,
    general_prefix_dir = None,
    other_links = [],
    clean_existing = True,
    is_wine_prefix = False,
    is_sandboxie_prefix = False,
    wine_setup = {},
    sandboxie_setup = {},
    is_32_bit = False,
    verbose = False,
    exit_on_failure = False):

    # Check prefix
    if not system.IsPathValid(prefix_dir):
        return False

    # Check general prefix
    if not system.IsPathValid(general_prefix_dir):
        return False

    # Create prefix
    if clean_existing:
        system.RemoveObject(prefix_dir, verbose = verbose, exit_on_failure = False)

    # Create general prefix subfolders
    for folder in config.computer_user_folders:
        system.MakeDirectory(
            dir = os.path.join(general_prefix_dir, folder),
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Get prefix c drive
    prefix_c_drive = GetRealDrivePath(
        prefix_dir = prefix_dir,
        drive = "c",
        is_wine_prefix = is_wine_prefix,
        is_sandboxie_prefix = is_sandboxie_prefix)

    # Setup wine prefix
    if is_wine_prefix:

        # Create wine prefix
        CreateWinePrefix(
            prefix_dir = prefix_dir,
            prefix_name = prefix_name,
            prefix_winver = prefix_winver,
            wine_setup = wine_setup,
            is_32_bit = is_32_bit,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Link prefix
        system.RemoveObject(
            obj = GetWineUserProfilePath(prefix_dir),
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        system.CreateSymlink(
            src = general_prefix_dir,
            dest = GetWineUserProfilePath(prefix_dir),
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Setup sandboxie prefix
    elif is_sandboxie_prefix:

        # Create sandboxie prefix
        CreateSandboxiePrefix(
            prefix_dir = prefix_dir,
            prefix_name = prefix_name,
            prefix_winver = prefix_winver,
            sandboxie_setup = sandboxie_setup,
            is_32_bit = is_32_bit,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Link other paths
    for other_link in other_links:
        path_from = other_link["from"]
        path_to = os.path.join(prefix_c_drive, other_link["to"])
        if not os.path.exists(path_from):
            continue
        system.RemoveObject(
            obj = path_to,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        system.CreateSymlink(
            src = path_from,
            dest = path_to,
            cwd = prefix_c_drive,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Check result
    return system.IsPathValid(prefix_dir)

###########################################################

# Translate path if necessary
def TranslatePathIfNecessary(path, program_exe, program_name):

    # Check params
    system.AssertIsValidPath(path, "path")
    system.AssertIsNonEmptyString(program_exe, "program_exe")
    system.AssertIsNonEmptyString(program_name, "program_name")

    # Check if prefix is necessary first
    should_run_via_wine = ShouldBeRunViaWine(program_exe)
    should_run_via_sandboxie = ShouldBeRunViaSandboxie(program_exe)
    if not should_run_via_wine and not should_run_via_sandboxie:
        return path

    # Translate path
    return TranslateRealPathToVirtualPath(
        path = path,
        prefix_dir = programs.GetProgramPrefixDir(program_name),
        prefix_name = programs.GetProgramPrefixName(program_name),
        is_wine_prefix = should_run_via_wine,
        is_sandboxie_prefix = should_run_via_sandboxie)

# Translate virtual path to real path
def TranslateVirtualPathToRealPath(
    path,
    prefix_dir = None,
    prefix_name = None,
    is_wine_prefix = False,
    is_sandboxie_prefix = False):

    # Check params
    system.AssertIsValidPath(path, "path")

    # Check prefix type
    if not is_wine_prefix and not is_sandboxie_prefix:
        return path

    # Check prefix
    if not prefix_dir:
        prefix_dir = GetPrefix(
            name = prefix_name,
            is_wine_prefix = is_wine_prefix,
            is_sandboxie_prefix = is_sandboxie_prefix)
    if not prefix_dir:
        return None

    # Get path info
    path_info = GetPrefixPathInfo(
        path = path,
        prefix_dir = prefix_dir,
        is_virtual_path = True,
        is_real_path = False,
        is_wine_prefix = is_wine_prefix,
        is_sandboxie_prefix = is_sandboxie_prefix)
    if not path_info:
        return None

    # Return real path
    return path_info["real"]

# Translate real path to virtual path
def TranslateRealPathToVirtualPath(
    path,
    prefix_dir = None,
    prefix_name = None,
    is_wine_prefix = False,
    is_sandboxie_prefix = False):

    # Check params
    system.AssertIsValidPath(path, "path")

    # Check prefix type
    if not is_wine_prefix and not is_sandboxie_prefix:
        return path

    # Check prefix
    if not prefix_dir:
        prefix_dir = GetPrefix(
            name = prefix_name,
            is_wine_prefix = is_wine_prefix,
            is_sandboxie_prefix = is_sandboxie_prefix)
    if not prefix_dir:
        return None

    # Get path info
    path_info = GetPrefixPathInfo(
        path = path,
        prefix_dir = prefix_dir,
        is_virtual_path = False,
        is_real_path = True,
        is_wine_prefix = is_wine_prefix,
        is_sandboxie_prefix = is_sandboxie_prefix)
    if not path_info:
        return None

    # Return virtual path
    return path_info["virtual"]

# Transfer from sandbox
def TransferFromSandbox(
    path,
    keep_in_sandbox = False,
    prefix_dir = None,
    prefix_name = None,
    is_wine_prefix = False,
    is_sandboxie_prefix = False,
    verbose = False,
    exit_on_failure = False):

    # Check params
    system.AssertIsValidPath(path, "path")

    # Get real path
    real_path = TranslateVirtualPathToRealPath(
        path = path,
        prefix_dir = prefix_dir,
        prefix_name = prefix_name,
        is_wine_prefix = is_wine_prefix,
        is_sandboxie_prefix = is_sandboxie_prefix)
    if not real_path:
        return

    # Ignore if paths are the same
    if os.path.normpath(path) == os.path.normpath(real_path):
        return

    # Ignore if not present in sandbox
    if not os.path.exists(real_path):
        return

    # Transfer from sandbox
    if keep_in_sandbox:
        if os.path.isdir(real_path):
            system.CopyContents(real_path, path, verbose = verbose, exit_on_failure = exit_on_failure)
        else:
            system.CopyFileOrDirectory(real_path, path, verbose = verbose, exit_on_failure = exit_on_failure)
    else:
        if os.path.isdir(real_path):
            system.MoveContents(real_path, path, verbose = verbose, exit_on_failure = exit_on_failure)
        else:
            system.MoveFileOrDirectory(real_path, path, verbose = verbose, exit_on_failure = exit_on_failure)

###########################################################
