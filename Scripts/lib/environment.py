# Imports
import os, os.path
import sys
import getpass
import time
import signal
import ntpath
import importlib

# Custom imports
lib_folder = os.path.realpath(os.path.dirname(__file__))
sys.path.append(lib_folder)
import config
import command
import system
import metadata
import programs

###########################################################

# Determine if windows platform
def IsWindowsPlatform():
    return sys.platform.startswith("win32")

# Determine if linux platform
def IsLinuxPlatform():
    return sys.platform.startswith("linux")

# Determine if mac platform
def IsMacPlatform():
    return sys.platform.startswith("darwin")

# Determine if unix platform
def IsUnixPlatform():
    return IsMacPlatform() or IsLinuxPlatform()

# Determine if wine platform
def IsWinePlatform():
    return IsLinuxPlatform()

# Determine if sandboxie platform
def IsSandboxiePlatform():
    return IsWindowsPlatform()

# Get current platform
def GetCurrentPlatform():
    if IsWindowsPlatform():
        return "windows"
    elif IsLinuxPlatform():
        return "linux"
    elif IsMacPlatform():
        return "macos"
    return None

# Get current timestamp
def GetCurrentTimestamp():
    return int(time.time())

###########################################################

# Get current screen resolution
def GetCurrentScreenResolution():

    # Linux
    if IsLinuxPlatform():
        output = command.RunOutputCommand(
            cmd = ["xdpyinfo"],
            options = command.CommandOptions(shell = True))
        for line in output.split("\n"):
            if "dimensions:" in line:
                line_tokens = line.split()
                if len(line_tokens) < 2:
                    continue
                dimensions = line_tokens[1].split("x")
                return (int(dimensions[0]), int(dimensions[1]))

    # Other
    else:
        import pyautogui
        size = pyautogui.size()
        return (size.width, size.height)

# Set screen resolution
def SetScreenResolution(width, height, colors, verbose = False, exit_on_failure = False):

    # Get tool
    nircmd_tool = None
    if programs.IsToolInstalled("NirCmd"):
        nircmd_tool = programs.GetToolProgram("NirCmd")
    if not nircmd_tool:
        return False

    # Get resolution command
    resolution_cmd = [
        nircmd_tool,
        "setdisplay",
        str(width),
        str(height),
        str(colors)
    ]

    # Set resolution
    command.RunBlockingCommand(
        cmd = resolution_cmd,
        options = command.CommandOptions(
            shell = True),
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    return True

# Restore default screen resolution
def RestoreDefaultScreenResolution(verbose = False, exit_on_failure = False):

    # Ignore if already at the default resolution
    current_w, current_h = GetCurrentScreenResolution()
    is_default_w = (current_w == config.default_screen_resolution_w)
    is_default_h = (current_h == config.default_screen_resolution_h)
    if is_default_w and is_default_h:
        return True

    # Set the new resolution otherwise
    return SetScreenResolution(
        width = config.default_screen_resolution_w,
        height = config.default_screen_resolution_h,
        colors = config.default_screen_resolution_c,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

###########################################################

# Get system tool
def GetSystemTool(tool_exe):
    system_tool = None
    if command.IsRunnableCommand(tool_exe, config.default_system_tools_dirs):
        system_tool = command.GetRunnableCommandPath(tool_exe, config.default_system_tools_dirs)
    return system_tool

# Get system tools
def GetSystemTools():
    system_tool_names = []
    if IsWindowsPlatform():
        system_tool_names = config.default_system_tools_names_windows
    elif IsLinuxPlatform():
        system_tool_names = config.default_system_tools_names_linux
    return system_tool_names

# Determine if system tools are installed
def AreSystemToolsInstalled():
    for system_tool in GetSystemTools():
        has_tool = command.IsRunnableCommand(system_tool, config.default_system_tools_dirs)
        if not has_tool:
            return False
    return True

###########################################################

# Determine if program is 32-bit windows
def IsProgramWindows32(program_path):

    # Get file cmd
    file_cmd = command.GetRunnableCommandPath(
        config.default_file_exe,
        config.default_system_tools_dirs)

    # Check file output
    output = command.RunOutputCommand(
        cmd = [file_cmd, program_path])
    return ("PE32 executable" in output)

# Determine if program is 64-bit windows
def IsProgramWindows64Bit(program_path):

    # Get file cmd
    file_cmd = command.GetRunnableCommandPath(
        config.default_file_exe,
        config.default_system_tools_dirs)

    # Check file output
    output = command.RunOutputCommand(
        cmd = [file_cmd, program_path])
    return ("PE32+ executable" in output)

###########################################################

# Determine if symlinks are supported
def AreSymlinksSupported():
    if IsUnixPlatform():
        return True
    else:
        test_file_src = os.path.join(config.default_user_dir, ".symsrc")
        test_file_dest = os.path.join(config.default_user_dir, ".symdest")
        if os.path.islink(test_file_dest):
            return True
        system.TouchFile(test_file_src)
        system.CreateSymlink(test_file_src, test_file_dest)
        return os.path.islink(test_file_dest)
    return False

# Determine if user is root
def IsUserRoot():
    if IsWindowsPlatform():
        try:
            import pyuac
            return pyuac.isUserAdmin()
        except:
            return False
    else:
        return os.getuid() == 0

# Run as root
def RunAsRoot(func):
    if not callable(func):
        return
    if IsWindowsPlatform():
        try:
            import pyuac
            if not pyuac.isUserAdmin():
                pyuac.runAsAdmin()
            else:
                func()
        except ModuleNotFoundError as e:
            func()
        except:
            raise

# Run as root if necessary
def RunAsRootIfNecessary(func):
    if callable(func):
        func()

###########################################################

# Find active processes
def FindActiveNamedProcesses(process_names = []):
    import psutil
    process_objs = []
    try:
        for proc in psutil.process_iter():
            for process_name in process_names:
                if process_name == proc.name():
                    process_objs.append(proc)
                elif ntpath.basename(process_name) == ntpath.basename(proc.name()):
                    process_objs.append(proc)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
        pass
    return process_objs

# Kill active processes
def KillActiveNamedProcesses(process_names = []):
    import psutil
    try:
        for proc in FindActiveNamedProcesses(process_names):
            proc.kill()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
        print(e)

# Interrupt active processes
def InterruptActiveNamedProcesses(process_names = []):
    import psutil
    try:
        for proc in FindActiveNamedProcesses(process_names):
            if hasattr(signal, "CTRL_C_EVENT"):
                proc.send_signal(signal.CTRL_C_EVENT)
            else:
                proc.send_signal(signal.SIGINT)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
        print(e)

# Wait for processes
def WaitForNamedProcesses(process_names = []):
    import psutil
    try:
        for proc in FindActiveNamedProcesses(process_names):
            while True:
                if not proc.is_running():
                    break
                time.sleep(1)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
        print(e)

###########################################################

# Determine if environment variable is set
def IsEnvironmentVariableSet(environment_var):
    if not isinstance(environment_var, str):
        return False
    return (environment_var in os.environ)

# Determine if environment variable is set to a specific value
def IsEnvironmentVariableSetToExpectedValue(environment_var, expected_value):
    if not isinstance(environment_var, str):
        return False
    return (environment_var in os.environ) and (GetEnvironmentVariable(environment_var) == expected_value)

# Get environment variable
def GetEnvironmentVariable(environment_var):
    if not isinstance(environment_var, str):
        return ""
    if environment_var in os.environ:
        return os.environ[environment_var]
    return ""

# Set environment variable
def SetEnvironmentVariable(environment_var, new_value, verbose = False, exit_on_failure = False):
    if not isinstance(environment_var, str) or len(environment_var) == 0:
        return
    if not isinstance(new_value, str) or len(new_value) == 0:
        return
    if IsWindowsPlatform():
        allow_processing = False
        powershell = False
        set_cmd = ["setx", environment_var, new_value]
        if environment_var == config.environment_path:
            allow_processing = True
            powershell = True
            set_cmd = "[System.Environment]::SetEnvironmentVariable('%s', '%s', 'User')" % (environment_var, new_value)
        try:
            command.RunExceptionCommand(
                cmd = set_cmd,
                options = command.CommandOptions(
                    allow_processing = allow_processing,
                    force_powershell = powershell),
                verbose = verbose)
        except Exception as e:
            if exit_on_failure:
                print("Unable to set environment variable %s to '%s'" % (environment_var, new_value))
                print(e)
                sys.exit(1)
            return
    else:
        system.TouchFile(
            src = config.default_environment_script,
            verbose = False,
            exit_on_failure = exit_on_failure)
        system.AppendLineToFile(
            src = config.default_login_script,
            line = "source %s" % config.default_environment_script,
            verbose = False,
            exit_on_failure = exit_on_failure)
        system.AppendLineToFile(
            src = config.default_environment_script,
            line = "export %s=\"%s\"" % (environment_var, new_value),
            verbose = verbose,
            exit_on_failure = exit_on_failure)

# Add environment path
def AddEnvironmentPath(path, verbose = False, exit_on_failure = False):
    if not system.IsPathValid(path) or not os.path.isabs(path):
        return
    if path in GetEnvironmentVariable(config.environment_path):
        return
    new_path = path + config.os_envpathsep + "$" + config.environment_path
    if IsWindowsPlatform():
        new_path = path + config.os_envpathsep + GetEnvironmentVariable(config.environment_path)
    SetEnvironmentVariable(
        environment_var = config.environment_path,
        new_value = new_path,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

# Set environment variables
def SetEnvironmentVariables(verbose = False, exit_on_failure = False):
    SetEnvironmentVariable(config.environment_local_cache_root_dir, GetLocalCacheRootDir(), verbose = verbose)
    SetEnvironmentVariable(config.environment_remote_cache_root_dir, GetRemoteCacheRootDir(), verbose = verbose)
    SetEnvironmentVariable(config.environment_sync_root_dir, GetSyncRootDir(), verbose = verbose)
    SetEnvironmentVariable(config.environment_repositories_root_dir, GetRepositoriesRootDir(), verbose = verbose)
    SetEnvironmentVariable(config.environment_storage_root_dir, GetStorageRootDir(), verbose = verbose)
    SetEnvironmentVariable(config.environment_network_share_base_location, GetNetworkShareBaseLocation(), verbose = verbose)
    SetEnvironmentVariable(config.environment_network_share_storage_folder, GetNetworkShareStorageFolder(), verbose = verbose)
    SetEnvironmentVariable(config.environment_network_share_cache_folder, GetNetworkShareCacheFolder(), verbose = verbose)
    SetEnvironmentVariable(config.environment_network_share_username, GetNetworkShareUsername(), verbose = verbose)
    SetEnvironmentVariable(config.environment_network_share_password, GetNetworkSharePassword(), verbose = verbose)
    SetEnvironmentVariable(config.environment_launchrom_program, GetLaunchRomProgram(), verbose = verbose)

# Set environment path
def SetEnvironmentPath(verbose = False, exit_on_failure = False):
    AddEnvironmentPath(GetScriptsBinDir(), verbose = verbose, exit_on_failure = exit_on_failure)

# Clear environment variables
def ClearEnvironmentVariables(verbose = False, exit_on_failure = False):
    if IsWindowsPlatform():
        for environment_var in config.environment_vars:
            clear_cmd = "[System.Environment]::SetEnvironmentVariable('%s', $null, 'User')" % environment_var
            try:
                command.RunExceptionCommand(
                    cmd = clear_cmd,
                    options = command.CommandOptions(
                        force_powershell = True),
                    verbose = verbose)
            except Exception as e:
                if exit_on_failure:
                    print("Unable to clear environment variables")
                    print(e)
                    sys.exit(1)
                return
    else:
        system.RemoveFile(
            file = config.default_environment_script,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

###########################################################

# Get python program
def GetPythonProgram():
    if command.IsRunnableCommand(config.default_python_exe, config.default_python_install_dirs):
        return command.GetRunnableCommandPath(config.default_python_exe, config.default_python_install_dirs)
    elif command.IsRunnableCommand(config.default_python3_exe, config.default_python_install_dirs):
        return command.GetRunnableCommandPath(config.default_python3_exe, config.default_python_install_dirs)
    return config.default_python_exe

# Get python virtual environment program
def GetPythonVirtualEnvProgram(program):
    if IsWindowsPlatform():
        return os.path.join(config.default_python_venv_dir, "Scripts", program)
    else:
        return os.path.join(config.default_python_venv_dir, "bin", program)

# Get python virtual environment interpreter
def GetPythonVirtualEnvInterpreter():
    return GetPythonVirtualEnvProgram(config.default_python_exe)

# Get required python modules
def GetRequiredPythonModules():
    if IsWindowsPlatform():
        return config.required_python_modules_all + config.required_python_modules_windows
    elif IsLinuxPlatform():
        return config.required_python_modules_all + config.required_python_modules_linux
    return []

# Setup python environment
def SetupPythonEnvironment(verbose = False):
    command.RunCheckedCommand(
        cmd = [
            GetPythonProgram(),
            "-m",
            "venv",
            config.default_python_venv_dir
        ],
        options = command.CommandOptions(
            allow_processing = False),
        verbose = verbose)

# Install python module
def InstallPythonModule(module, verbose = False):
    command.RunCheckedCommand(
        cmd = [
            GetPythonVirtualEnvInterpreter(),
            "-m",
            config.default_python_pip_exe,
            "install",
            "--upgrade",
            module
        ],
        options = command.CommandOptions(
            allow_processing = False),
        verbose = verbose)

# Install python modules
def InstallPythonModules(modules, verbose = False):
    if modules and len(modules) > 0:
        for module in modules:
            InstallPythonModule(module, verbose)

# Import python module
def ImportPythonModule(module_path, module_name):
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

###########################################################

# Get required system packages
def GetRequiredSystemPackages():
    if IsWindowsPlatform():
        return config.required_system_packages_all + config.required_system_packages_windows
    elif IsLinuxPlatform():
        return config.required_system_packages_all + config.required_system_packages_linux
    return []

# Install system package
def InstallSystemPackage(package, verbose = False):
    if IsLinuxPlatform():
        command.RunCheckedCommand(
            cmd = [
                "sudo",
                "apt",
                "-y",
                "install",
                "--no-install-recommends",
                package
            ],
            options = command.CommandOptions(
                allow_processing = False),
            verbose = verbose)

# Install system packages
def InstallSystemPackages(packages, verbose = False):
    if packages and len(packages) > 0:
        for package in packages:
            InstallSystemPackage(package, verbose)

###########################################################

# Get local cache root dir
def GetLocalCacheRootDir():
    if IsEnvironmentVariableSet(config.environment_local_cache_root_dir):
        return GetEnvironmentVariable(config.environment_local_cache_root_dir)
    else:
        if IsWindowsPlatform():
            return config.default_local_cache_dir_windows
        elif IsLinuxPlatform():
            return config.default_local_cache_dir_linux
    return ""

# Get remote cache root dir
def GetRemoteCacheRootDir():
    if IsEnvironmentVariableSet(config.environment_remote_cache_root_dir):
        return GetEnvironmentVariable(config.environment_remote_cache_root_dir)
    else:
        if IsWindowsPlatform():
            return config.default_remote_cache_dir_windows
        elif IsLinuxPlatform():
            return config.default_remote_cache_dir_linux
    return ""

# Get sync root dir
def GetSyncRootDir():
    if IsEnvironmentVariableSet(config.environment_sync_root_dir):
        return GetEnvironmentVariable(config.environment_sync_root_dir)
    else:
        if IsWindowsPlatform():
            return config.default_sync_dir_windows
        elif IsLinuxPlatform():
            return config.default_sync_dir_linux
    return ""

# Get repositories root dir
def GetRepositoriesRootDir():
    if IsEnvironmentVariableSet(config.environment_repositories_root_dir):
        return GetEnvironmentVariable(config.environment_repositories_root_dir)
    else:
        if IsWindowsPlatform():
            return config.default_repositories_dir_windows
        elif IsLinuxPlatform():
            return config.default_repositories_dir_linux
    return ""

# Get storage root dir
def GetStorageRootDir():
    if IsEnvironmentVariableSet(config.environment_storage_root_dir):
        return GetEnvironmentVariable(config.environment_storage_root_dir)
    else:
        if IsWindowsPlatform():
            return config.default_storage_dir_windows
        elif IsLinuxPlatform():
            return config.default_storage_dir_linux
    return ""

# Get network share base location
def GetNetworkShareBaseLocation():
    if IsEnvironmentVariableSet(config.environment_network_share_base_location):
        return GetEnvironmentVariable(config.environment_network_share_base_location)
    return config.default_network_share_base_location

# Get network share storage folder
def GetNetworkShareStorageFolder():
    if IsEnvironmentVariableSet(config.environment_network_share_storage_folder):
        return GetEnvironmentVariable(config.environment_network_share_storage_folder)
    return config.default_network_share_storage_folder

# Get network share cache folder
def GetNetworkShareCacheFolder():
    if IsEnvironmentVariableSet(config.environment_network_share_cache_folder):
        return GetEnvironmentVariable(config.environment_network_share_cache_folder)
    return config.default_network_share_cache_folder

# Get network share user
def GetNetworkShareUsername():
    if IsEnvironmentVariableSet(config.environment_network_share_username):
        return GetEnvironmentVariable(config.environment_network_share_username)
    return config.default_network_share_username

# Get network share password
def GetNetworkSharePassword():
    if IsEnvironmentVariableSet(config.environment_network_share_password):
        return GetEnvironmentVariable(config.environment_network_share_password)
    return config.default_network_share_password

# Get launch rom program
def GetLaunchRomProgram():
    if IsEnvironmentVariableSet(config.environment_launchrom_program):
        return GetEnvironmentVariable(config.environment_launchrom_program)
    else:
        return os.path.join(GetScriptsBinDir(), "launch_rom" + GetScriptsCommandExtension())

###########################################################

# Get scripts root dir
def GetScriptsRootDir():
    return os.path.join(GetRepositoriesRootDir(), config.project_name, "Scripts")

# Get tools root dir
def GetToolsRootDir():
    return os.path.join(GetRepositoriesRootDir(), config.project_name, "Tools")

# Get emulators root dir
def GetEmulatorsRootDir():
    return os.path.join(GetRepositoriesRootDir(), config.project_name, "Emulators")

# Get metadata root dir
def GetMetadataRootDir():
    return os.path.join(GetRepositoriesRootDir(), config.project_name, "Metadata")

###########################################################

# Get synced gaming root dir
def GetSyncedGamingRootDir():
    return os.path.join(GetSyncRootDir(), "Gaming")

# Get synced gaming assets root dir
def GetSyncedGamingAssetsRootDir():
    return os.path.join(GetSyncedGamingRootDir(), "Assets")

# Get synced game asset dir
def GetSyncedGameAssetDir(game_category, game_subcategory, asset_type):
    return os.path.join(GetSyncedGamingAssetsRootDir(), game_category, game_subcategory, asset_type)

# Get synced game asset file
def GetSyncedGameAssetFile(game_category, game_subcategory, game_name, asset_type):
    asset_file = "%s%s" % (game_name, config.asset_type_extensions[asset_type])
    return os.path.join(GetSyncedGamingAssetsRootDir(), game_category, game_subcategory, asset_type, asset_file)

# Get synced gaming emulators root dir
def GetSyncedGamingEmulatorsRootDir():
    return os.path.join(GetSyncedGamingRootDir(), "Emulators")

# Get synced game emulator setup dir
def GetSyncedGameEmulatorSetupDir(emu_name):
    return os.path.join(GetSyncedGamingEmulatorsRootDir(), emu_name, "Setup")

# Get synced gaming saves root dir
def GetSyncedGamingSavesRootDir():
    return os.path.join(GetSyncedGamingRootDir(), "Saves")

# Get synced game save dir
def GetSyncedGameSaveDir(game_category, game_subcategory, game_name):
    if game_category == config.game_category_computer:
        letter = metadata.DeriveGameLetterFromName(game_name)
        return os.path.join(GetSyncedGamingSavesRootDir(), game_category, game_subcategory, letter, game_name)
    else:
        return os.path.join(GetSyncedGamingSavesRootDir(), game_category, game_subcategory, game_name)

# Get synced music root dir
def GetSyncedMusicRootDir():
    return os.path.join(GetSyncRootDir(), "Music")

# Get synced photos root dir
def GetSyncedPhotosRootDir():
    return os.path.join(GetSyncRootDir(), "Photos")

# Get synced programs root dir
def GetSyncedProgramsRootDir():
    return os.path.join(GetSyncRootDir(), "Programs")

###########################################################

# Get pegasus metadata root dir
def GetPegasusMetadataRootDir():
    return os.path.join(GetMetadataRootDir(), "Pegasus")

# Get pegasus metadata file
def GetPegasusMetadataFile(game_category, game_subcategory):
    return os.path.join(GetPegasusMetadataRootDir(), config.game_supercategory_roms, game_category, game_subcategory, "metadata.pegasus.txt")

# Get pegasus metadata asset dir
def GetPegasusMetadataAssetDir(game_category, game_subcategory, asset_type):
    return os.path.join(GetPegasusMetadataRootDir(), config.game_supercategory_roms, game_category, game_subcategory, asset_type)

# Get gamelist metadata root dir
def GetGameListMetadataRootDir():
    return os.path.join(GetMetadataRootDir(), "GameList")

# Get gamelist metadata file
def GetGameListMetadataFile(game_category, game_subcategory):
    return os.path.join(GetGameListMetadataRootDir(), config.game_supercategory_roms, game_category, game_subcategory + ".txt")

# Get published metadata root dir
def GetPublishedMetadataRootDir():
    return os.path.join(GetMetadataRootDir(), "Published")

# Get hashes metadata root dir
def GetHashesMetadataRootDir():
    return os.path.join(GetMetadataRootDir(), "Hashes")

# Get hashes metadata file
def GetHashesMetadataFile(game_supercategory, game_category, game_subcategory):
    return os.path.join(GetHashesMetadataRootDir(), "Main", game_supercategory, game_category, game_subcategory + ".txt")

# Get misc metadata root dir
def GetMiscMetadataRootDir():
    return os.path.join(GetMetadataRootDir(), "Misc")

# Get main metadata hashes dir
def GetMainMetadataHashesDir():
    return os.path.join(GetHashesMetadataRootDir(), "Main")

# Get disc metadata hashes dir
def GetDiscMetadataHashesDir():
    return os.path.join(GetHashesMetadataRootDir(), "Disc")

# Get json metadata root dir
def GetJsonMetadataRootDir():
    return os.path.join(GetMetadataRootDir(), "Json")

# Get json roms metadata root dir
def GetJsonRomsMetadataRootDir():
    return os.path.join(GetJsonMetadataRootDir(), config.game_supercategory_roms)

# Get json rom metadata file
def GetJsonRomMetadataFile(game_category, game_subcategory, game_name):
    if game_category == config.game_category_computer:
        letter = metadata.DeriveGameLetterFromName(game_name)
        return os.path.join(GetJsonRomsMetadataRootDir(), game_category, game_subcategory, letter, game_name, game_name + ".json")
    else:
        return os.path.join(GetJsonRomsMetadataRootDir(), game_category, game_subcategory, game_name, game_name + ".json")

###########################################################

# Get scripts bin dir
def GetScriptsBinDir():
    return os.path.join(GetScriptsRootDir(), "bin")

# Get scripts lib dir
def GetScriptsLibDir():
    return os.path.join(GetScriptsRootDir(), "lib")

# Get scripts third party lib dir
def GetScriptsThirdPartyLibDir():
    return os.path.join(GetScriptsLibDir(), "thirdparty")

# Get scripts command extension
def GetScriptsCommandExtension():
    if IsWindowsPlatform():
        return ".bat"
    else:
        return ""

# Get scripts executable extension
def GetScriptsExecutableExtension():
    if IsWindowsPlatform():
        return ".exe"
    else:
        return ""

###########################################################

# Get gaming storage root dir
def GetGamingStorageRootDir():
    return os.path.join(GetStorageRootDir(), "Gaming")

# Get gaming cache root dir
def GetGamingLocalCacheRootDir():
    return os.path.join(GetLocalCacheRootDir(), "Gaming")

# Get gaming cache root dir
def GetGamingRemoteCacheRootDir():
    return os.path.join(GetRemoteCacheRootDir(), "Gaming")

# Get rom root dir
def GetRomRootDir():
    return os.path.join(GetGamingStorageRootDir(), config.game_supercategory_roms)

# Get install rom root dir
def GetInstallRomRootDir():
    return os.path.join(GetGamingRemoteCacheRootDir(), config.game_supercategory_installs)

# Get rom dir
def GetRomDir(rom_category, rom_subcategory, rom_name):
    if rom_category == config.game_category_computer:
        letter = metadata.DeriveGameLetterFromName(rom_name)
        return os.path.join(GetRomRootDir(), rom_category, rom_subcategory, letter, rom_name)
    else:
        return os.path.join(GetRomRootDir(), rom_category, rom_subcategory, rom_name)

# Get install rom dir
def GetInstallRomDir(rom_category, rom_subcategory, rom_name):
    if rom_category == config.game_category_computer:
        letter = metadata.DeriveGameLetterFromName(rom_name)
        return os.path.join(GetInstallRomRootDir(), rom_category, rom_subcategory, letter, rom_name)
    else:
        return os.path.join(GetInstallRomRootDir(), rom_category, rom_subcategory, rom_name)

# Get dlc root dir
def GetDLCRootDir():
    return os.path.join(GetGamingStorageRootDir(), config.game_supercategory_dlc)

# Get update root dir
def GetUpdateRootDir():
    return os.path.join(GetGamingStorageRootDir(), config.game_supercategory_updates)

# Get supercategory root dir
def GetSupercategoryRootDir(supercategory):
    if supercategory == config.game_supercategory_roms:
        return GetRomRootDir()
    elif supercategory == config.game_supercategory_dlc:
        return GetDLCRootDir()
    elif supercategory == config.game_supercategory_updates:
        return GetUpdateRootDir()

###########################################################

# Get cached roms root dir
def GetCachedRomsRootDir():
    return os.path.join(GetGamingLocalCacheRootDir(), config.game_supercategory_roms)

# Get cached rom dir
def GetCachedRomDir(rom_category, rom_subcategory, rom_name):
    return os.path.join(GetCachedRomsRootDir(), rom_category, rom_subcategory, rom_name)

# Get cached saves root dir
def GetCachedSavesRootDir():
    return os.path.join(GetGamingLocalCacheRootDir(), config.game_supercategory_saves)

# Get cached save dir
def GetCachedSaveDir(rom_category, rom_subcategory, rom_name, rom_subname = None):
    if rom_subname:
        return os.path.join(GetCachedSavesRootDir(), rom_category, rom_subcategory, rom_name, rom_subname)
    else:
        return os.path.join(GetCachedSavesRootDir(), rom_category, rom_subcategory, rom_name)

# Get cached setup root dir
def GetCachedSetupRootDir():
    return os.path.join(GetGamingLocalCacheRootDir(), config.game_supercategory_setup)

# Get cached setup dir
def GetCachedSetupDir(rom_category, rom_subcategory, rom_name):
    return os.path.join(GetCachedSetupRootDir(), rom_category, rom_subcategory, rom_name)

###########################################################

# Get game names
def GetGameNames(base_dir, game_category, game_subcategory):
    game_names = []
    base_path = os.path.join(base_dir, game_category, game_subcategory)
    if game_category == config.game_category_computer:
        for game_letter in system.GetDirectoryContents(base_path):
            for game_name in system.GetDirectoryContents(os.path.join(base_path, game_letter)):
                game_names.append(game_name)
    else:
        for game_name in system.GetDirectoryContents(base_path):
            game_names.append(game_name)
    return game_names

###########################################################
