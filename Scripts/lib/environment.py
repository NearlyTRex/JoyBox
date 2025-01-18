# Imports
import os, os.path
import sys
import signal
import ntpath
import time

# Local imports
import config
import command
import system
import gameinfo
import platforms
import ini

###########################################################
# System capabilities
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

# Get home directory
def GetHomeDirectory():
    return os.path.expanduser("~")

# Get cookie directory
def GetCookieDirectory():
    return system.JoinPaths(GetHomeDirectory(), "Cookies")

# Get log directory
def GetLogDirectory():
    return system.JoinPaths(GetHomeDirectory(), "Logs")

# Get log file
def GetLogFile():
    return system.JoinPaths(GetLogDirectory(), "output.log")

# Determine if symlinks are supported
def AreSymlinksSupported():
    if IsUnixPlatform():
        return True
    else:
        test_file_src = system.JoinPaths(os.path.expanduser("~"), ".symsrc")
        test_file_dest = system.JoinPaths(os.path.expanduser("~"), ".symdest")
        if os.path.islink(test_file_dest):
            return True
        system.TouchFile(test_file_src)
        system.CreateSymlink(test_file_src, test_file_dest)
        return os.path.islink(test_file_dest)
    return False

###########################################################
# Python modules
###########################################################

# Import python module package
def ImportPythonModulePackage(module_path, module_name):
    import importlib
    if system.IsPathDirectory(module_path):
        if module_name not in sys.modules:
            sys.path.append(module_path)
            module = importlib.import_module(module_name)
            return module
        else:
            return sys.modules[module_name]
    return None

# Import python module file
def ImportPythonModuleFile(module_path, module_name):
    import importlib.util
    if system.IsPathFile(module_path):
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return sys.modules[module_name]
    return None

###########################################################
# Root access
###########################################################

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

###########################################################
# Process management
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
        system.LogError(e)

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
        system.LogError(e)

# Wait for processes
def WaitForNamedProcesses(process_names = []):
    import psutil
    try:
        for proc in FindActiveNamedProcesses(process_names):
            while True:
                if not proc.is_running():
                    break
                system.SleepProgram(1)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
        system.LogError(e)

###########################################################
# Tools
###########################################################

# Get tools root dir
def GetToolsRootDir():
    return ini.GetIniPathValue("UserData.Dirs", "tools_dir")

###########################################################
# Emulators
###########################################################

# Get emulators root dir
def GetEmulatorsRootDir():
    return ini.GetIniPathValue("UserData.Dirs", "emulators_dir")

###########################################################
# Locker
###########################################################

# Get local locker root dir
def GetLocalLockerRootDir():
    return ini.GetIniPathValue("UserData.Dirs", "local_locker_dir")

# Get remote locker root dir
def GetRemoteLockerRootDir():
    return ini.GetIniPathValue("UserData.Dirs", "remote_locker_dir")

# Get locker root dir
def GetLockerRootDir(source_type = None):
    if source_type == config.SourceType.REMOTE:
        return GetRemoteLockerRootDir()
    else:
        return GetLocalLockerRootDir()

###########################################################
# Locker - Development
###########################################################

# Get locker development root dir
def GetLockerDevelopmentRootDir(source_type = None):
    return system.JoinPaths(
        GetLockerRootDir(source_type),
        config.LockerType.DEVELOPMENT)

# Get locker development archives root dir
def GetLockerDevelopmentArchivesRootDir(source_type = None):
    return system.JoinPaths(
        GetLockerDevelopmentRootDir(source_type),
        "Archive")

###########################################################
# Locker - Gaming
###########################################################

# Get locker gaming root dir
def GetLockerGamingRootDir(source_type = None):
    return system.JoinPaths(
        GetLockerRootDir(source_type),
        config.LockerType.GAMING)

# Get locker gaming roms root dir
def GetLockerGamingRomsRootDir(source_type = None):
    return system.JoinPaths(
        GetLockerGamingRootDir(source_type),
        config.Supercategory.ROMS)

# Get locker gaming dlc root dir
def GetLockerGamingDLCRootDir(source_type = None):
    return system.JoinPaths(
        GetLockerGamingRootDir(source_type),
        config.Supercategory.DLC)

# Get locker gaming update root dir
def GetLockerGamingUpdateRootDir(source_type = None):
    return system.JoinPaths(
        GetLockerGamingRootDir(source_type),
        config.Supercategory.UPDATES)

# Get locker gaming tags root dir
def GetLockerGamingTagsRootDir(source_type = None):
    return system.JoinPaths(
        GetLockerGamingRootDir(source_type),
        config.Supercategory.TAGS)

###########################################################
# Locker - Gaming - Files
###########################################################

# Get locker gaming files offset
def GetLockerGamingFilesOffset(game_supercategory, game_category, game_subcategory, game_name):
    game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)
    game_name_path = gameinfo.DeriveGameNamePathFromName(game_name, game_platform)
    return system.JoinPaths(
        game_supercategory,
        game_category,
        game_subcategory,
        game_name_path)

# Get locker gaming files dir
def GetLockerGamingFilesDir(game_supercategory, game_category, game_subcategory, game_name, source_type = None):
    return system.JoinPaths(
        GetLockerGamingRootDir(source_type),
        GetLockerGamingFilesOffset(game_supercategory, game_category, game_subcategory, game_name))

###########################################################
# Locker - Gaming - Saves
###########################################################

# Get locker gaming saves root dir
def GetLockerGamingSavesRootDir(source_type = None):
    return system.JoinPaths(
        GetLockerGamingRootDir(source_type),
        config.Supercategory.SAVES)

# Get locker gaming save dir
def GetLockerGamingSaveDir(game_category, game_subcategory, game_name, source_type = None):
    game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)
    game_name_path = gameinfo.DeriveGameNamePathFromName(game_name, game_platform)
    return system.JoinPaths(
        GetLockerGamingSavesRootDir(source_type),
        game_category,
        game_subcategory,
        game_name_path)

###########################################################
# Locker - Gaming - Assets
###########################################################

# Get locker gaming assets root dir
def GetLockerGamingAssetsRootDir(source_type = None):
    return system.JoinPaths(
        GetLockerGamingRootDir(source_type),
        config.Supercategory.ASSETS)

# Get locker gaming asset dir
def GetLockerGamingAssetDir(game_category, game_subcategory, asset_type, source_type = None):
    return system.JoinPaths(
        GetLockerGamingAssetsRootDir(source_type),
        game_category,
        game_subcategory,
        asset_type)

# Get locker gaming asset file
def GetLockerGamingAssetFile(game_category, game_subcategory, game_name, asset_type, source_type = None):
    asset_file = "%s%s" % (game_name, asset_type.cval())
    return system.JoinPaths(
        GetLockerGamingAssetsRootDir(source_type),
        game_category,
        game_subcategory,
        asset_type,
        asset_file)

###########################################################
# Locker - Gaming - Emulators
###########################################################

# Get locker gaming emulators root dir
def GetLockerGamingEmulatorsRootDir(source_type = None):
    return system.JoinPaths(
        GetLockerGamingRootDir(source_type),
        config.Supercategory.EMULATORS)

# Get locker gaming emulator binaries dir
def GetLockerGamingEmulatorBinariesDir(emu_name, emu_platform, source_type = None):
    return system.JoinPaths(
        GetLockerGamingEmulatorsRootDir(source_type),
        emu_name,
        "Binaries",
        emu_platform)

# Get locker gaming emulator setup dir
def GetLockerGamingEmulatorSetupDir(emu_name, source_type = None):
    return system.JoinPaths(
        GetLockerGamingEmulatorsRootDir(source_type),
        emu_name,
        "Setup")

###########################################################
# Locker - Music
###########################################################

# Get locker music root dir
def GetLockerMusicRootDir(source_type = None):
    return system.JoinPaths(
        GetLockerRootDir(source_type),
        config.LockerType.MUSIC)

###########################################################
# Locker - Photos
###########################################################

# Get locker photos root dir
def GetLockerPhotosRootDir(source_type = None):
    return system.JoinPaths(
        GetLockerRootDir(source_type),
        config.LockerType.PHOTOS)

###########################################################
# Locker - Programs
###########################################################

# Get locker programs root dir
def GetLockerProgramsRootDir(source_type = None):
    return system.JoinPaths(
        GetLockerRootDir(source_type),
        config.LockerType.PROGRAMS)

# Get locker programs tools root dir
def GetLockerProgramsToolsRootDir(source_type = None):
    return system.JoinPaths(
        GetLockerProgramsRootDir(source_type),
        "Tools")

# Get locker program tool dir
def GetLockerProgramToolDir(tool_name, tool_platform = None, source_type = None):
    if tool_platform:
        return system.JoinPaths(
            GetLockerProgramsToolsRootDir(source_type),
            tool_name,
            tool_platform)
    else:
        return system.JoinPaths(
            GetLockerProgramsToolsRootDir(source_type),
            tool_name)

###########################################################
# Metadata
###########################################################

# Get metadata root dir
def GetMetadataRootDir():
    return ini.GetIniPathValue("UserData.Dirs", "metadata_dir")

# Get pegasus metadata root dir
def GetPegasusMetadataRootDir():
    return system.JoinPaths(GetMetadataRootDir(), "Pegasus")

# Get pegasus metadata file
def GetPegasusMetadataFile(game_category, game_subcategory):
    return system.JoinPaths(
        GetPegasusMetadataRootDir(),
        config.Supercategory.ROMS,
        game_category,
        game_subcategory,
        "metadata.pegasus.txt")

# Get pegasus metadata asset dir
def GetPegasusMetadataAssetDir(game_category, game_subcategory, asset_type):
    return system.JoinPaths(
        GetPegasusMetadataRootDir(),
        config.Supercategory.ROMS,
        game_category,
        game_subcategory,
        asset_type)

# Get metadata file
def GetMetadataFile(game_category, game_subcategory, metadata_format = config.MetadataFormatType.PEGASUS):
    if metadata_format == config.MetadataFormatType.PEGASUS:
        return GetPegasusMetadataFile(game_category, game_subcategory)
    return None

# Check if file is a metadata file
def IsMetadataFile(metadata_file):
    return metadata_file.endswith("metadata.pegasus.txt")

# Get published metadata root dir
def GetPublishedMetadataRootDir():
    return system.JoinPaths(GetMetadataRootDir(), "Published")

# Get misc metadata root dir
def GetMiscMetadataRootDir():
    return system.JoinPaths(GetMetadataRootDir(), "Misc")

# Get hashes metadata root dir
def GetHashesMetadataRootDir():
    return system.JoinPaths(GetMetadataRootDir(), "Hashes")

# Get hashes metadata file
def GetHashesMetadataFile(game_supercategory, game_category, game_subcategory):
    return system.JoinPaths(
        GetHashesMetadataRootDir(),
        game_supercategory,
        game_category,
        game_subcategory.val() + ".json")

# Get json metadata root dir
def GetJsonMetadataRootDir():
    return system.JoinPaths(GetMetadataRootDir(), "Json")

# Get json rom metadata dir
def GetJsonMetadataDir(game_supercategory, game_category, game_subcategory):
    return system.JoinPaths(
        GetJsonMetadataRootDir(),
        game_supercategory,
        game_category,
        game_subcategory)

# Get json metadata file
def GetJsonMetadataFile(game_supercategory, game_category, game_subcategory, game_name):
    game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)
    game_name_path = gameinfo.DeriveGameNamePathFromName(game_name, game_platform)
    return system.JoinPaths(
        GetJsonMetadataDir(game_supercategory, game_category, game_subcategory),
        game_name_path,
        game_name + ".json")

# Get json metadata ignore file
def GetJsonMetadataIgnoreFile(game_supercategory, game_category, game_subcategory):
    return system.JoinPaths(
        GetJsonMetadataDir(game_supercategory, game_category, game_subcategory),
        "ignores.json")

###########################################################
# Scripts
###########################################################

# Get scripts root dir
def GetScriptsRootDir():
    return ini.GetIniPathValue("UserData.Dirs", "scripts_dir")

# Get scripts bin dir
def GetScriptsBinDir():
    return system.JoinPaths(GetScriptsRootDir(), "bin")

# Get scripts icons dir
def GetScriptsIconsDir():
    return system.JoinPaths(GetScriptsRootDir(), "icons")

# Get scripts lib dir
def GetScriptsLibDir():
    return system.JoinPaths(GetScriptsRootDir(), "lib")

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
# Cache
###########################################################

# Get cache root dir
def GetCacheRootDir():
    return ini.GetIniPathValue("UserData.Dirs", "cache_dir")

# Get cache gaming root dir
def GetCacheGamingRootDir():
    return system.JoinPaths(
        GetCacheRootDir(),
        config.LockerType.GAMING)

# Get cache gaming roms root dir
def GetCacheGamingRomsRootDir():
    return system.JoinPaths(
        GetCacheGamingRootDir(),
        config.Supercategory.ROMS)

# Get cache gaming rom dir
def GetCacheGamingRomDir(game_category, game_subcategory, game_name):
    return system.JoinPaths(
        GetCacheGamingRomsRootDir(),
        game_category,
        game_subcategory,
        game_name)

# Get cache gaming install root dir
def GetCacheGamingInstallsRootDir():
    return system.JoinPaths(
        GetCacheGamingRootDir(),
        config.Supercategory.INSTALLS)

# Get cache gaming install dir
def GetCacheGamingInstallDir(game_category, game_subcategory, game_name):
    game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)
    game_name_path = gameinfo.DeriveGameNamePathFromName(game_name, game_platform)
    return system.JoinPaths(
        GetCacheGamingInstallsRootDir(),
        game_category,
        game_subcategory,
        game_name_path)

# Get cache gaming saves root dir
def GetCacheGamingSavesRootDir():
    return system.JoinPaths(
        GetCacheGamingRootDir(),
        config.Supercategory.SAVES)

# Get cache gaming save dir
def GetCacheGamingSaveDir(game_category, game_subcategory, game_name, save_type = None):
    if save_type:
        return system.JoinPaths(
            GetCacheGamingSavesRootDir(),
            game_category,
            game_subcategory,
            game_name,
            save_type)
    else:
        return system.JoinPaths(
            GetCacheGamingSavesRootDir(),
            game_category,
            game_subcategory,
            game_name)

# Get cache gaming setup root dir
def GetCacheGamingSetupRootDir():
    return system.JoinPaths(
        GetCacheGamingRootDir(),
        config.Supercategory.SETUP)

# Get cache gaming setup dir
def GetCacheGamingSetupDir(game_category, game_subcategory, game_name):
    return system.JoinPaths(
        GetCacheGamingSetupRootDir(),
        game_category,
        game_subcategory,
        game_name)
