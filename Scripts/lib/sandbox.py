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
import archive
import chd
import gui
import ini

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
def GetBlockingProcesses(options, initial_processes = []):
    blocking_processes = copy.deepcopy(initial_processes)
    if options.is_wine_prefix():
        blocking_processes += GetWineBlockingProcesses()
    elif options.is_sandboxie_prefix():
        blocking_processes += GetSandboxieBlockingProcesses()
    return blocking_processes

###########################################################

# Get wine prefix
def GetWinePrefix(options):
    return system.JoinPaths(programs.GetToolPathConfigValue("Wine", "sandbox_dir"), options.get_prefix_name())

# Get sandboxie prefix
def GetSandboxiePrefix(options):
    return system.JoinPaths(programs.GetToolPathConfigValue("Sandboxie", "sandbox_dir"), options.get_prefix_name())

# Get prefix
def GetPrefix(options):
    prefix_dir = None
    if options.get_prefix_name():
        if options.is_wine_prefix():
            prefix_dir = GetWinePrefix(options)
        elif options.is_sandboxie_prefix():
            prefix_dir = GetSandboxiePrefix(options)
    return prefix_dir

###########################################################

# Get wine real drive path
def GetWineRealDrivePath(options, drive):
    if drive.lower() == "c":
        return system.JoinPaths(options.get_prefix_dir(), "drive_c")
    else:
        return system.JoinPaths(options.get_prefix_dir(), "dosdevices", drive.lower() + ":")

# Get sandboxie real drive path
def GetSandboxieRealDrivePath(options, drive):
    return system.JoinPaths(options.get_prefix_dir(), "drive", drive.upper())

# Get real drive path
def GetRealDrivePath(options, drive):
    real_drive_path = None
    if options.is_wine_prefix():
        real_drive_path = GetWineRealDrivePath(options, drive)
    elif options.is_sandboxie_prefix():
        real_drive_path = GetSandboxieRealDrivePath(options, drive)
    return real_drive_path

# Get real c drive path
def GetRealCDrivePath(options):
    return GetRealDrivePath(options, "c")

###########################################################

# Get wine user profile path
def GetWineUserProfilePath(options):
    return system.NormalizeFilePath(system.JoinPaths(options.get_prefix_dir(), "drive_c", "users", getpass.getuser()))

# Get sandboxie user profile path
def GetSandboxieUserProfilePath(options):
    return system.NormalizeFilePath(system.JoinPaths(options.get_prefix_dir(), "user", "current"))

# Get user profile path
def GetUserProfilePath(options):
    user_profile_dir = None
    if options.is_wine_prefix():
        user_profile_dir = GetWineUserProfilePath(options)
    elif options.is_sandboxie_prefix():
        user_profile_dir = GetSandboxieUserProfilePath(options)
    return user_profile_dir

###########################################################

# Get wine public profile path
def GetWinePublicProfilePath(options):
    return system.NormalizeFilePath(system.JoinPaths(options.get_prefix_dir(), "drive_c", "users", "Public"))

# Get sandboxie public profile path
def GetSandboxiePublicProfilePath(options):
    return system.NormalizeFilePath(system.JoinPaths(options.get_prefix_dir(), "drive", "C", "Public"))

# Get public profile path
def GetPublicProfilePath(options):
    public_profile_dir = None
    if options.is_wine_prefix():
        public_profile_dir = GetWinePublicProfilePath(options)
    elif options.is_sandboxie_prefix():
        public_profile_dir = GetSandboxiePublicProfilePath(options)
    return public_profile_dir

###########################################################

# Install wine dlls
def InstallWineDlls(
    options,
    dlls_32 = [],
    dlls_64 = [],
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    wine_c_drive = GetWineRealDrivePath(options, "c")
    wine_system32_dir = system.JoinPaths(wine_c_drive, "windows", "system32")
    wine_syswow64_dir = system.JoinPaths(wine_c_drive, "windows", "syswow64")
    if options.is_32_bit():
        for lib32 in dlls_32:
            system.CopyFileOrDirectory(
                src = lib32,
                dest = wine_system32_dir,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
    else:
        for lib64 in dlls_64:
            system.CopyFileOrDirectory(
                src = lib64,
                dest = system.JoinPaths(wine_c_drive, "windows", "system32"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        for lib32 in dlls_32:
            system.CopyFileOrDirectory(
                src = lib32,
                dest = wine_syswow64_dir,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

# Install sandboxie dlls
def InstallSandboxieDlls(
    options,
    dlls_32 = [],
    dlls_64 = [],
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    pass

# Install dlls
def InstallDlls(
    options,
    dlls_32 = [],
    dlls_64 = [],
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if options.is_wine_prefix():
        InstallWineDlls(
            options = options,
            dlls_32 = dlls_32,
            dlls_64 = dlls_64,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    elif options.is_sandboxie_prefix():
        InstallSandboxieDlls(
            options = options,
            dlls_32 = dlls_32,
            dlls_64 = dlls_64,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

###########################################################

# Restore registry
def RestoreRegistry(
    options,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get registry dir
    registry_dir = system.JoinPaths(user_profile_dir, config.computer_folder_registry)

    # Get registry file
    registry_file = ""
    if options.get_prefix_name() == config.PrefixType.SETUP:
        registry_file = system.JoinPaths(registry_dir, config.registry_filename_setup)
    elif options.get_prefix_name() == config.PrefixType.GAME:
        registry_file = system.JoinPaths(registry_dir, config.registry_filename_game)
    if not system.DoesPathExist(registry_file):
        return True

    # Import registry file
    return registry.ImportRegistryFile(
        registry_file = registry_file,
        options = options,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Backup registry
def BackupRegistry(
    options,
    registry_keys = [],
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Ignore empty keys
    if len(registry_keys) == 0:
        return True

    # Get registry dir
    registry_dir = system.JoinPaths(user_profile_dir, config.computer_folder_registry)

    # Get registry file
    registry_file = ""
    if options.get_prefix_name() == config.PrefixType.SETUP:
        registry_file = system.JoinPaths(registry_dir, config.registry_filename_setup)
    elif options.get_prefix_name() == config.PrefixType.GAME:
        registry_file = system.JoinPaths(registry_dir, config.registry_filename_game)

    # Get registry export keys
    registry_export_keys = []
    if options.get_prefix_name() == config.PrefixType.SETUP:
        registry_export_keys = config.registry_export_keys_setup
    elif options.get_prefix_name() == config.PrefixType.GAME:
        registry_export_keys = config.registry_export_keys_game

    # Get registry ignore keys
    registry_ignore_keys = []
    if options.get_prefix_name() == config.PrefixType.SETUP:
        registry_ignore_keys = config.ignored_registry_keys_setup
    elif options.get_prefix_name() == config.PrefixType.GAME:
        registry_ignore_keys = config.ignored_registry_keys_game

    # Backup registry
    return registry.BackupUserRegistry(
        registry_file = registry_file,
        options = options,
        export_keys = registry_export_keys,
        ignore_keys = registry_ignore_keys,
        keep_keys = registry_keys,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

###########################################################

# Find first available real drive path
def FindFirstAvailableRealDrivePath(options):

    # Check params
    system.AssertPathExists(options.get_prefix_dir(), "prefix_dir")

    # Only go through potentially available drives
    for letter in config.drives_regular:

        # Get drive path and check if its available
        drive_path = GetRealDrivePath(
            options = options,
            drive = letter)
        if not system.DoesPathExist(drive_path):
            return drive_path

    # Nothing available
    return None

# Find first taken real drive path
def FindFirstTakenRealDrivePath(src, options):

    # Check params
    system.AssertPathExists(src, "src")
    system.AssertPathExists(options.get_prefix_dir(), "prefix_dir")

    # Only go through potentially available drives
    for letter in config.drives_regular:

        # Get drive path and check if its available
        drive_path = GetRealDrivePath(
            options = options,
            drive = letter)
        if system.DoesPathExist(drive_path):
            if src == system.ResolveSymlink(drive_path):
                return drive_path

    # Nothing found
    return None

# Mount disc image
def MountDiscImage(
    src,
    mount_dir,
    options,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check params
    system.AssertPathExists(src, "src")

    # Mount disc
    success = chd.MountDiscCHD(
        chd_file = src,
        mount_dir = mount_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Mount directory
    success = MountDirectory(
        src = mount_dir,
        options = options,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Unmount disc image
def UnmountDiscImage(
    src,
    mount_dir,
    options,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check params
    system.AssertPathExists(src, "src")

    # Unmount disc
    success = UnmountDirectory(
        src = mount_dir,
        options = options,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Unmount directory
    success = chd.UnmountDiscCHD(
        chd_file = src,
        mount_dir = mount_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Mount directory
def MountDirectory(
    src,
    options,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check params
    system.AssertPathExists(src, "src")
    system.AssertPathExists(options.get_prefix_dir(), "prefix_dir")

    # Get first available drive path
    drive_path = FindFirstAvailableRealDrivePath(options)
    if not system.IsPathValid(drive_path):
        return False

    # Create symlink
    return system.CreateSymlink(
        src = src,
        dest = drive_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Unmount directory
def UnmountDirectory(
    src,
    options,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check params
    system.AssertPathExists(src, "src")
    system.AssertPathExists(options.get_prefix_dir(), "prefix_dir")

    # Get first taken drive path
    drive_path = FindFirstTakenRealDrivePath(src, options)
    if not system.IsPathValid(drive_path):
        return False

    # Create symlink
    return system.RemoveSymlink(
        src = src,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Unmount all mounted drives
def UnmountAllMountedDrives(
    options,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check params
    system.AssertPathExists(options.get_prefix_dir(), "prefix_dir")

    # Only go through potentially available drives
    for letter in config.drives_regular:

        # Get real drive path
        drive_path = GetRealDrivePath(
            options = options,
            drive = letter)

        # Remove symlink
        system.RemoveSymlink(
            src = drive_path,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Should be successful
    return True

###########################################################

# Build token map
def BuildTokenMap(
    store_install_dir = None,
    game_install_dir = None,
    setup_base_dir = None,
    hdd_base_dir = None,
    disc_base_dir = None,
    disc_files = [],
    use_drive_letters = False):

    # Create token map
    token_map = {}

    # Add paths
    if store_install_dir:
        token_map[config.token_store_install_dir] = store_install_dir
    if game_install_dir:
        token_map[config.token_game_install_dir] = game_install_dir
    if setup_base_dir:
        token_map[config.token_setup_main_root] = setup_base_dir
    if hdd_base_dir:
        token_map[config.token_hdd_main_root] = hdd_base_dir
        token_map[config.token_dos_main_root] = system.JoinPaths(hdd_base_dir, config.computer_folder_dos)
        token_map[config.token_scumm_main_root] = system.JoinPaths(hdd_base_dir, config.computer_folder_scumm)

    # Add discs
    disc_letter_index = 0
    for disc_file in disc_files:

        # Get drive letter
        disc_letter_drive = config.drives_regular[disc_letter_index]
        disc_letter_index += 1

        # Get file basename
        disc_file_basename = system.GetFilenameBasename(disc_file)

        # Find which token to use
        disc_token_to_use = None
        for disc_token, disc_name in config.token_disc_names.items():
            if disc_name in disc_file:
                disc_token_to_use = disc_token
                break
        else:
            disc_token_to_use = config.token_disc_main_root

        # Add entry
        if disc_token_to_use:
            if use_drive_letters:
                token_map[disc_token_to_use] = "%s:/" % disc_letter_drive
            else:
                if disc_base_dir:
                    token_map[disc_token_to_use] = system.JoinPaths(disc_base_dir, disc_file_basename)
                else:
                    token_map[disc_token_to_use] = disc_file_basename

    # Return token map
    return token_map

# Resolve path
def ResolvePath(
    path,
    token_map = {}):
    for token, replacement in token_map.items():
        if token in path:
            path = path.replace(token, replacement)
    return path

###########################################################

# Get prefix path info
def GetPrefixPathInfo(
    path,
    options,
    is_virtual_path = False,
    is_real_path = False):

    # Check path
    if not system.IsPathValid(path):
        return None

    # Check prefix
    if not options.has_valid_prefix_dir():
        return None

    # These are some potential types of paths
    # - /home/user/.wine/drive_c/foo/bar
    # - /home/user/.wine/dosdevices/c:/foo/bar
    # - C:/Sandboxie/Sandbox/Default/drives/C/foo/bar
    # - C:/foo/bar

    # Copy params
    new_path = copy.deepcopy(path)
    new_options = options.copy()

    # Normalize paths
    new_path = system.NormalizeFilePath(new_path, separator = config.os_pathsep)
    new_options.set_prefix_dir(system.NormalizeFilePath(new_options.get_prefix_dir(), separator = config.os_pathsep))

    # Fix path inconsistencies
    if new_options.is_wine_prefix():
        if is_virtual_path and new_path.startswith(config.drive_root_posix):
            is_virtual_path = False
            is_real_path = True

    # Initialize letter, offset, and base
    path_drive_letter = ""
    path_drive_offset = ""
    path_drive_extra = ""
    path_drive_base = ""

    # Path starts with prefix
    if new_path.startswith(new_options.get_prefix_dir()):

        # Find drive letter and offset
        if is_virtual_path:
            path_drive_letter = system.GetDirectoryDrive(new_path)
            path_drive_offset = new_path[len(system.GetDirectoryAnchor(new_path)):]
        elif is_real_path:
            path_drive_start = new_path[len(new_options.get_prefix_dir() + config.os_pathsep):]
            if new_options.is_wine_prefix():
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
            elif new_options.is_sandboxie_prefix():
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
            if new_options.is_wine_prefix():
                path_drive_base = system.JoinPaths(new_options.get_prefix_dir(), "dosdevices", path_drive_letter.lower() + ":")
            elif new_options.is_sandboxie_prefix():
                path_drive_base = system.JoinPaths(new_options.get_prefix_dir(), "drives", path_drive_letter.upper())
        elif is_real_path:
            path_drive_base = new_path[-len(path_drive_offset):]

    # Prefix and path are not related
    else:

        # Wine
        if new_options.is_wine_prefix():
            if is_virtual_path:
                path_drive_letter = system.GetDirectoryDrive(new_path)
            else:
                path_drive_letter = "z"
            path_drive_offset = new_path[len(system.GetDirectoryAnchor(new_path)):]
            path_drive_base = GetWineRealDrivePath(new_options.get_prefix_dir(), path_drive_letter)

        # Sandboxie
        elif new_options.is_sandboxie_prefix():
            path_drive_letter = system.GetDirectoryDrive(new_path)
            path_drive_offset = new_path[len(system.GetDirectoryAnchor(new_path)):]
            path_drive_extra = system.NormalizeFilePath(system.JoinPaths("Users", getpass.getuser()), separator = config.os_pathsep)
            if path_drive_offset.startswith(path_drive_extra):
                path_drive_base = GetSandboxieUserProfilePath(new_options.get_prefix_dir())
                path_drive_offset = path_drive_offset[len(path_drive_extra + config.os_pathsep):]
            else:
                path_drive_base = GetSandboxieRealDrivePath(new_options.get_prefix_dir(), path_drive_letter)

        # Neither
        else:
            path_drive_offset = new_path[len(system.GetDirectoryAnchor(new_path)):]
            path_drive_base = system.GetDirectoryDrive(new_path)
            if environment.IsWinePlatform():
                path_drive_letter = "z"
            else:
                path_drive_letter = system.GetDirectoryDrive(new_path)
            is_virtual_path = False
            is_real_path = True

    # Construct full virtual and real paths
    path_full_virtual = ""
    path_full_real = ""
    if is_virtual_path:
        path_full_virtual = new_path
        path_full_real = system.JoinPaths(path_drive_base, path_drive_offset)
    elif is_real_path:
        path_full_virtual += path_drive_letter.upper() + ":" + config.os_pathsep
        path_full_virtual += path_drive_extra + config.os_pathsep
        path_full_virtual += path_drive_offset
        path_full_real = new_path

    # Check for consistency
    if is_virtual_path:
        system.AssertCondition(
            condition = (new_path == path_full_virtual),
            description = "Original virtual path must match constructed virtual path")
    elif is_real_path:
        system.AssertCondition(
            condition = (new_path == path_full_real),
            description = "Original real path must match constructed real path")

    # Return path info
    info = {}
    info["path"] = system.NormalizeFilePath(new_path)
    info["prefix"] = system.NormalizeFilePath(new_options.get_prefix_dir())
    info["is_virtual"] = is_virtual_path
    info["is_real"] = is_real_path
    info["is_wine"] = new_options.is_wine_prefix()
    info["is_sandboxie"] = new_options.is_sandboxie_prefix()
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

###########################################################

# Setup prefix environment
def SetupPrefixEnvironment(
    cmd,
    options = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check options
    if not options:
        options = command.CreateCommandOptions()

    # Ignore non-prefix environments
    if not options.is_prefix():
        return (cmd, options)

    # Copy params
    new_cmd = copy.deepcopy(cmd)
    new_options = options.copy()

    # Modify for wine
    if new_options.is_wine_prefix():

        # Add blocking processes
        new_options.add_blocking_processes(GetWineBlockingProcesses())

        # Improve performance by not showing everything
        # To show only errors, change to fixme-all
        new_options.set_env_var("WINEDEBUG", "-all")

        # Set prefix location
        if new_options.has_valid_prefix_dir():
            new_options.set_env_var("WINEPREFIX", new_options.get_prefix_dir())

        # Set prefix bitness
        if new_options.is_32_bit():
            new_options.set_env_var("WINEARCH", "win32")
        else:
            new_options.set_env_var("WINEARCH", "win64")

        # Set prefix overrides
        wine_overrides = ["winemenubuilder.exe=d"]
        wine_overrides += new_options.get_overrides()
        new_options.set_env_var("WINEDLLOVERRIDES", ";".join(wine_overrides))

        # Map the current working directory to the prefix
        if new_options.is_prefix_mapped_cwd() and new_options.has_valid_cwd():
            cwd_drive = GetRealDrivePath(
                options = new_options,
                drive = config.drive_prefix_cwd)
            if system.IsPathValid(cwd_drive):
                system.RemoveSymlink(
                    src = cwd_drive,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
                system.CreateSymlink(
                    src = new_options.get_cwd(),
                    dest = cwd_drive,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)

    # Modify for sandboxie
    elif new_options.is_sandboxie_prefix():

        # Add blocking processes
        new_options.add_blocking_processes(GetSandboxieBlockingProcesses())

    # Return results
    return (new_cmd, new_options)

# Setup prefix command
def SetupPrefixCommand(
    cmd,
    options = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check options
    if not options:
        options = command.CreateCommandOptions()

    # Ignore non-prefix commands
    if not options.is_prefix():
        return (cmd, options)

    # Get original command info
    orig_cmd_starter = command.GetStarterCommand(cmd)
    orig_cmd_list = command.CreateCommandList(cmd)
    if len(orig_cmd_list) == 0:
        return (cmd, options)

    # Copy params
    new_cmd = []
    new_options = options.copy()

    # Create command
    if new_options.is_wine_prefix():
        new_cmd = [GetWineCommand()]
        if new_options.use_virtual_desktop():
            new_cmd += ["explorer", "/desktop=" + new_options.get_desktop_dimensions()]
    elif new_options.is_sandboxie_prefix():
        new_cmd = [
            GetSandboxieCommand(),
            "/box:%s" % options.get_prefix_name().val()
        ]
        if new_options.get_prefix_name() == config.PrefixType.TOOL:
            new_cmd += ["/hide_window"]

    # Adjust command based on executable type
    if orig_cmd_starter.endswith(".lnk"):
        info = system.GetLinkInfo(
            lnk_path = orig_cmd_starter,
            lnk_base_path = options.get_lnk_base_path())
        has_valid_target = system.DoesPathExist(info["target"])
        has_valid_cwd = system.DoesPathExist(info["cwd"])
        if not has_valid_target or not has_valid_cwd:
            gui.DisplayErrorPopup(
                title_text = "Unable to resolve LNK file",
                message_text = "Unable to resolve LNK file %s to an actual target" % orig_cmd_starter)
        new_cmd += [info["target"]]
        new_cmd += info["args"]
        new_options.set_cwd(info["cwd"])
    elif orig_cmd_starter.endswith(".bat"):
        if options.is_sandboxie_prefix():
            new_cmd += ["cmd", "/c"]
        new_cmd += orig_cmd_list
    else:
        new_cmd += orig_cmd_list

    # Sync cwd to prefix cwd
    new_options.sync_cwd_to_prefix_cwd()

    # Return results
    return (new_cmd, new_options)

###########################################################

# Cleanup wine
def CleanupWine(cmd, options, verbose = False, pretend_run = False, exit_on_failure = False):

    # Get wine server tool
    wine_server_tool = programs.GetToolProgram("WineServer")

    # Kill processes running under wine
    command.RunBlockingCommand(
        cmd = [wine_server_tool, "-k"],
        options = command.CreateCommandOptions(
            shell = True),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Kill wine itself
    environment.KillActiveNamedProcesses([wine_server_tool])

# Cleanup sandboxie
def CleanupSandboxie(cmd, options, verbose = False, pretend_run = False, exit_on_failure = False):
    pass

###########################################################

# Create wine prefix
def CreateWinePrefix(
    options,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Make directory
    system.MakeDirectory(
        src = options.get_prefix_dir(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get wine boot tool
    wine_boot_tool = programs.GetToolProgram("WineBoot")

    # Get wine tricks tool
    wine_tricks_tool = programs.GetToolProgram("WineTricks")

    # Copy params
    new_options = options.copy()
    new_options.set_is_wine_prefix(True)

    # Initialize prefix
    cmds_to_run = []
    cmds_to_run.append([wine_boot_tool])
    if len(new_options.get_tricks()) > 0:
        cmds_to_run.append(["winetricks " + trick for trick in new_options.get_tricks()])
    for cmd in cmds_to_run:
        new_options.set_blocking_processes([command.GetStarterCommand(cmd)])
        new_cmd, new_options = SetupPrefixEnvironment(
            cmd = cmd,
            options = new_options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        code = command.RunBlockingCommand(
            cmd = new_cmd,
            options = new_options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if code != 0:
            return False

    # Creation successful
    return True

# Create sandboxie prefix
def CreateSandboxiePrefix(
    options,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Make directories
    system.MakeDirectory(
        src = options.get_prefix_dir(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    system.MakeDirectory(
        src = GetSandboxieRealDrivePath(options.get_prefix_dir(), "C"),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    system.MakeDirectory(
        src = GetSandboxieUserProfilePath(options.get_prefix_dir()),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get sandboxie ini tool
    sandboxie_ini_tool = programs.GetToolProgram("SandboxieIni")

    # Copy params
    new_options = options.copy()
    new_options.set_is_sandboxie_prefix(True)
    new_options.set_blocking_processes([sandboxie_ini_tool])
    new_options.set_shell(True)

    # Set sandboxie param
    def SetSandboxieBoxParam(options, param, value):
        cmd = [sandboxie_ini_tool, "set", sandbox_options.get_prefix_name().val(), param, value]
        new_cmd, new_options = SetupPrefixEnvironment(
            cmd = cmd,
            options = options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        command.RunBlockingCommand(
            cmd = new_cmd,
            options = new_options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Initialize prefix
    SetSandboxieBoxParam(new_options, "Enabled", "y")
    SetSandboxieBoxParam(new_options, "FileRootPath", new_options.get_prefix_dir())
    SetSandboxieBoxParam(new_options, "BlockNetParam", "n")
    SetSandboxieBoxParam(new_options, "BlockNetworkFiles", "y")
    SetSandboxieBoxParam(new_options, "RecoverFolder", "%Desktop%")
    SetSandboxieBoxParam(new_options, "BorderColor", "#00ffff,off,6")
    SetSandboxieBoxParam(new_options, "ConfigLevel", "10")
    SetSandboxieBoxParam(new_options, "BoxNameTitle", "-")
    SetSandboxieBoxParam(new_options, "CopyLimitKb", "-1")
    SetSandboxieBoxParam(new_options, "NoSecurityIsolation", "y")
    SetSandboxieBoxParam(new_options, "Template", "OpenBluetooth")

    # Creation successful
    return True

# Create basic prefix
def CreateBasicPrefix(
    options,
    clean_existing = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check prefix
    if not options.has_valid_prefix_dir():
        return False

    # Clean prefix
    if clean_existing:
        system.RemoveObject(
            obj = options.get_prefix_dir(),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Setup wine prefix
    if options.is_wine_prefix():

        # Create wine prefix
        CreateWinePrefix(
            options = options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Replace symlinked directories
        system.ReplaceSymlinkedDirectories(
            src = GetWineUserProfilePath(options),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Setup sandboxie prefix
    elif options.is_sandboxie_prefix():

        # Create sandboxie prefix
        CreateSandboxiePrefix(
            options = options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Check result
    return options.has_valid_prefix_dir()

# Create linked prefix
def CreateLinkedPrefix(
    options,
    other_links = [],
    clean_existing = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check prefix
    if not options.has_valid_prefix_dir():
        return False

    # Check general prefix
    if not options.has_valid_general_prefix_dir():
        return False

    # Clean prefix
    if clean_existing:
        system.RemoveObject(
            obj = options.get_prefix_dir(),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)

    # Create general prefix subfolders
    for folder in config.computer_user_folders:
        system.MakeDirectory(
            src = system.JoinPaths(options.get_general_prefix_dir(), folder),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Get prefix c drive
    prefix_c_drive = GetRealCDrivePath(options)

    # Setup wine prefix
    if options.is_wine_prefix():

        # Create wine prefix
        CreateWinePrefix(
            options = options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Link prefix
        system.RemoveObject(
            obj = GetWineUserProfilePath(options),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        system.MakeDirectory(
            src = system.GetDirectoryParent(GetWineUserProfilePath(options)),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        system.CreateSymlink(
            src = options.get_general_prefix_dir(),
            dest = GetWineUserProfilePath(options),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Setup sandboxie prefix
    elif options.is_sandboxie_prefix():

        # Create sandboxie prefix
        CreateSandboxiePrefix(
            options = options,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Link other paths
    for other_link in other_links:
        path_from = other_link["from"]
        path_to = system.JoinPaths(prefix_c_drive, other_link["to"])
        if not system.DoesPathExist(path_from):
            continue
        system.RemoveObject(
            obj = path_to,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        system.MakeDirectory(
            src = system.GetDirectoryParent(path_to),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        system.CreateSymlink(
            src = path_from,
            dest = path_to,
            cwd = prefix_c_drive,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Check result
    return options.has_valid_prefix_dir()

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

    # Get prefix options
    options = command.CreateCommandOptions(
        prefix_dir = programs.GetProgramPrefixDir(program_name),
        prefix_name = programs.GetProgramPrefixName(program_name),
        is_wine_prefix = should_run_via_wine,
        is_sandboxie_prefix = should_run_via_sandboxie)

    # Translate path
    return TranslateRealPathToVirtualPath(
        path = path,
        options = options)

# Translate virtual path to real path
def TranslateVirtualPathToRealPath(
    path,
    options):

    # Check params
    system.AssertIsValidPath(path, "path")

    # Check prefix type
    if not options.is_prefix():
        return path

    # Check prefix
    if not options.get_prefix_dir():
        options.set_prefix_dir(GetPrefix(options))
    if not options.get_prefix_dir():
        return None

    # Get path info
    path_info = GetPrefixPathInfo(
        path = path,
        options = options,
        is_virtual_path = True,
        is_real_path = False)
    if not path_info:
        return None

    # Return real path
    return path_info["real"]

# Translate real path to virtual path
def TranslateRealPathToVirtualPath(
    path,
    options):

    # Check params
    system.AssertIsValidPath(path, "path")

    # Check prefix type
    if not options.is_prefix():
        return path

    # Check prefix
    if not options.get_prefix_dir():
        options.set_prefix_dir(GetPrefix(options))
    if not options.get_prefix_dir():
        return None

    # Get path info
    path_info = GetPrefixPathInfo(
        path = path,
        options = options,
        is_virtual_path = False,
        is_real_path = True)
    if not path_info:
        return None

    # Return virtual path
    return path_info["virtual"]

# Transfer from sandbox
def TransferFromSandbox(
    path,
    options,
    keep_in_sandbox = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check params
    system.AssertIsValidPath(path, "path")

    # Get real path
    real_path = TranslateVirtualPathToRealPath(
        path = path,
        options = options)
    if not real_path:
        return

    # Ignore if paths are the same
    if os.path.normpath(path) == os.path.normpath(real_path):
        return

    # Ignore if not present in sandbox
    if not system.DoesPathExist(real_path):
        return

    # Transfer from sandbox
    if keep_in_sandbox:
        if system.IsPathDirectory(real_path):
            system.CopyContents(
                src = real_path,
                dest = path,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        else:
            system.CopyFileOrDirectory(
                src = real_path,
                dest = path,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
    else:
        if system.IsPathDirectory(real_path):
            system.MoveContents(
                src = real_path,
                dest = path,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        else:
            system.MoveFileOrDirectory(
                src = real_path,
                dest = path,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

###########################################################
