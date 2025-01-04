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
    return os.path.join(GetHomeDirectory(), "Cookies")

# Get log directory
def GetLogDirectory():
    return os.path.join(GetHomeDirectory(), "Logs")

# Get log file
def GetLogFile():
    return os.path.join(GetLogDirectory(), "output.log")

# Determine if symlinks are supported
def AreSymlinksSupported():
    if IsUnixPlatform():
        return True
    else:
        test_file_src = os.path.join(os.path.expanduser("~"), ".symsrc")
        test_file_dest = os.path.join(os.path.expanduser("~"), ".symdest")
        if os.path.islink(test_file_dest):
            return True
        system.TouchFile(test_file_src)
        system.CreateSymlink(test_file_src, test_file_dest)
        return os.path.islink(test_file_dest)
    return False

###########################################################
# Python modules
###########################################################

# Import python module
def ImportPythonModule(module_path, module_name):
    import importlib.util
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return sys.modules[module_name]

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

# Get locker development root dir
def GetLockerDevelopmentRootDir(source_type = None):
    return os.path.join(
        GetLockerRootDir(source_type),
        config.LockerType.DEVELOPMENT.val())

# Get locker gaming root dir
def GetLockerGamingRootDir(source_type = None):
    return os.path.join(
        GetLockerRootDir(source_type),
        config.LockerType.GAMING.val())

# Get locker music root dir
def GetLockerMusicRootDir(source_type = None):
    return os.path.join(
        GetLockerRootDir(source_type),
        config.LockerType.MUSIC.val())

# Get locker photos root dir
def GetLockerPhotosRootDir(source_type = None):
    return os.path.join(
        GetLockerRootDir(source_type),
        config.LockerType.PHOTOS.val())

# Get locker programs root dir
def GetLockerProgramsRootDir(source_type = None):
    return os.path.join(
        GetLockerRootDir(source_type),
        config.LockerType.PROGRAMS.val())

# Get locker programs tools root dir
def GetLockerProgramsToolsRootDir(source_type = None):
    return os.path.join(
        GetLockerProgramsRootDir(source_type),
        "Tools")

# Get locker gaming assets root dir
def GetLockerGamingAssetsRootDir(source_type = None):
    return os.path.join(
        GetLockerGamingRootDir(source_type),
        config.Supercategory.ASSETS.val())

# Get locker gaming emulators root dir
def GetLockerGamingEmulatorsRootDir(source_type = None):
    return os.path.join(
        GetLockerGamingRootDir(source_type),
        config.Supercategory.EMULATORS.val())

# Get locker gaming roms root dir
def GetLockerGamingRomsRootDir(source_type = None):
    return os.path.join(
        GetLockerGamingRootDir(source_type),
        config.Supercategory.ROMS.val())

# Get locker gaming dlc root dir
def GetLockerGamingDLCRootDir(source_type = None):
    return os.path.join(
        GetLockerGamingRootDir(source_type),
        config.Supercategory.DLC.val())

# Get locker gaming update root dir
def GetLockerGamingUpdateRootDir(source_type = None):
    return os.path.join(
        GetLockerGamingRootDir(source_type),
        config.Supercategory.UPDATES.val())

# Get locker gaming tags root dir
def GetLockerGamingTagsRootDir(source_type = None):
    return os.path.join(
        GetLockerGamingRootDir(source_type),
        config.Supercategory.TAGS.val())

# Get locker gaming saves root dir
def GetLockerGamingSavesRootDir(source_type = None):
    return os.path.join(
        GetLockerGamingRootDir(source_type),
        config.Supercategory.SAVES.val())

# Get locker gaming supercategory root dir
def GetLockerGamingSupercategoryRootDir(supercategory, source_type = None):
    if supercategory == config.Supercategory.ASSETS:
        return GetLockerGamingAssetsRootDir(source_type)
    elif supercategory == config.Supercategory.EMULATORS:
        return GetLockerGamingEmulatorsRootDir(source_type)
    elif supercategory == config.Supercategory.ROMS:
        return GetLockerGamingRomsRootDir(source_type)
    elif supercategory == config.Supercategory.DLC:
        return GetLockerGamingDLCRootDir(source_type)
    elif supercategory == config.Supercategory.UPDATES:
        return GetLockerGamingUpdateRootDir(source_type)
    elif supercategory == config.Supercategory.TAGS:
        return GetLockerGamingTagsRootDir(source_type)
    elif supercategory == config.Supercategory.SAVES:
        return GetLockerGamingSavesRootDir(source_type)
    return None

# Get locker development archives root dir
def GetLockerDevelopmentArchivesRootDir(source_type = None):
    return os.path.join(GetLockerDevelopmentRootDir(source_type), "Archive")

# Get locker gaming asset dir
def GetLockerGamingAssetDir(game_category, game_subcategory, asset_type, source_type = None):
    return os.path.join(
        GetLockerGamingAssetsRootDir(source_type),
        game_category.val(),
        game_subcategory.val(),
        asset_type.val())

# Get locker gaming asset file
def GetLockerGamingAssetFile(game_category, game_subcategory, game_name, asset_type, source_type = None):
    asset_file = "%s%s" % (game_name, asset_type.cvalue())
    return os.path.join(
        GetLockerGamingAssetsRootDir(source_type),
        game_category.val(),
        game_subcategory.val(),
        asset_type.val(),
        asset_file)

# Get locker gaming emulator binaries dir
def GetLockerGamingEmulatorBinariesDir(emu_name, emu_platform, source_type = None):
    return os.path.join(
        GetLockerGamingEmulatorsRootDir(source_type),
        emu_name,
        "Binaries",
        emu_platform)

# Get locker gaming emulator setup dir
def GetLockerGamingEmulatorSetupDir(emu_name, source_type = None):
    return os.path.join(
        GetLockerGamingEmulatorsRootDir(source_type),
        emu_name,
        "Setup")

# Get locker gaming rom dir offset
def GetLockerGamingRomDirOffset(game_category, game_subcategory, game_name):
    game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)
    game_name_path = gameinfo.DeriveGameNamePathFromName(game_name, game_platform)
    return os.path.join(
        game_category.val(),
        game_subcategory.val(),
        game_name_path)

# Get locker gaming rom dir
def GetLockerGamingRomDir(game_category, game_subcategory, game_name, source_type = None):
    return os.path.join(
        GetLockerGamingRomsRootDir(source_type),
        GetLockerGamingRomDirOffset(game_category, game_subcategory, game_name))

# Get locker gaming rom category dir
def GetLockerGamingRomCategoryDir(game_category, game_subcategory, source_type = None):
    return os.path.join(
        GetLockerGamingRomsRootDir(source_type),
        game_category.val(),
        game_subcategory.val())

# Get locker gaming save dir
def GetLockerGamingSaveDir(game_category, game_subcategory, game_name, source_type = None):
    game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)
    game_name_path = gameinfo.DeriveGameNamePathFromName(game_name, game_platform)
    return os.path.join(
        GetLockerGamingSavesRootDir(source_type),
        game_category.val(),
        game_subcategory.val(),
        game_name_path)

# Get locker program tool dir
def GetLockerProgramToolDir(tool_name, tool_platform = None, source_type = None):
    if tool_platform:
        return os.path.join(
            GetLockerProgramsToolsRootDir(source_type),
            tool_name,
            tool_platform)
    else:
        return os.path.join(
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
    return os.path.join(GetMetadataRootDir(), "Pegasus")

# Get pegasus metadata file
def GetPegasusMetadataFile(game_category, game_subcategory):
    return os.path.join(
        GetPegasusMetadataRootDir(),
        config.Supercategory.ROMS.val(),
        game_category.val(),
        game_subcategory.val(),
        "metadata.pegasus.txt")

# Get pegasus metadata asset dir
def GetPegasusMetadataAssetDir(game_category, game_subcategory, asset_type):
    return os.path.join(
        GetPegasusMetadataRootDir(),
        config.Supercategory.ROMS.val(),
        game_category.val(),
        game_subcategory.val(),
        asset_type.val())

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
    return os.path.join(GetMetadataRootDir(), "Published")

# Get misc metadata root dir
def GetMiscMetadataRootDir():
    return os.path.join(GetMetadataRootDir(), "Misc")

# Get hashes metadata root dir
def GetHashesMetadataRootDir():
    return os.path.join(GetMetadataRootDir(), "Hashes")

# Get hashes metadata file
def GetHashesMetadataFile(game_supercategory, game_category, game_subcategory):
    return os.path.join(
        GetHashesMetadataRootDir(),
        game_supercategory.val(),
        game_category.val(),
        game_subcategory.val() + ".txt")

# Get json metadata root dir
def GetJsonMetadataRootDir():
    return os.path.join(GetMetadataRootDir(), "Json")

# Get json roms metadata root dir
def GetJsonRomsMetadataRootDir():
    return os.path.join(
        GetJsonMetadataRootDir(),
        config.Supercategory.ROMS.val())

# Get json rom metadata dir
def GetJsonRomMetadataDir(game_category, game_subcategory):
    return os.path.join(
        GetJsonRomsMetadataRootDir(),
        game_category.val(),
        game_subcategory.val())

# Get json rom metadata file
def GetJsonRomMetadataFile(game_category, game_subcategory, game_name):
    game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)
    game_name_path = gameinfo.DeriveGameNamePathFromName(game_name, game_platform)
    return os.path.join(
        GetJsonRomsMetadataRootDir(),
        game_category.val(),
        game_subcategory.val(),
        game_name_path,
        game_name + ".json")

# Get json rom metadata ignore file
def GetJsonRomMetadataIgnoreFile(game_category, game_subcategory):
    return os.path.join(
        GetJsonRomMetadataDir(game_category, game_subcategory),
        "ignores.json")

###########################################################
# Scripts
###########################################################

# Get scripts root dir
def GetScriptsRootDir():
    return ini.GetIniPathValue("UserData.Dirs", "scripts_dir")

# Get scripts bin dir
def GetScriptsBinDir():
    return os.path.join(GetScriptsRootDir(), "bin")

# Get scripts icons dir
def GetScriptsIconsDir():
    return os.path.join(GetScriptsRootDir(), "icons")

# Get scripts lib dir
def GetScriptsLibDir():
    return os.path.join(GetScriptsRootDir(), "lib")

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
    return os.path.join(
        GetCacheRootDir(),
        config.LockerType.GAMING.val())

# Get cache gaming roms root dir
def GetCacheGamingRomsRootDir():
    return os.path.join(
        GetCacheGamingRootDir(),
        config.Supercategory.ROMS.val())

# Get cache gaming rom dir
def GetCacheGamingRomDir(game_category, game_subcategory, game_name):
    return os.path.join(
        GetCacheGamingRomsRootDir(),
        game_category.val(),
        game_subcategory.val(),
        game_name)

# Get cache gaming install root dir
def GetCacheGamingInstallsRootDir():
    return os.path.join(
        GetCacheGamingRootDir(),
        config.Supercategory.INSTALLS.val())

# Get cache gaming install dir
def GetCacheGamingInstallDir(game_category, game_subcategory, game_name):
    game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)
    game_name_path = gameinfo.DeriveGameNamePathFromName(game_name, game_platform)
    return os.path.join(
        GetCacheGamingInstallsRootDir(),
        game_category.val(),
        game_subcategory.val(),
        game_name_path)

# Get cache gaming saves root dir
def GetCacheGamingSavesRootDir():
    return os.path.join(
        GetCacheGamingRootDir(),
        config.Supercategory.SAVES.val())

# Get cache gaming save dir
def GetCacheGamingSaveDir(game_category, game_subcategory, game_name, save_type = None):
    if save_type:
        return os.path.join(
            GetCacheGamingSavesRootDir(),
            game_category.val(),
            game_subcategory.val(),
            game_name,
            save_type.val())
    else:
        return os.path.join(
            GetCacheGamingSavesRootDir(),
            game_category.val(),
            game_subcategory.val(),
            game_name)

# Get cache gaming setup root dir
def GetCacheGamingSetupRootDir():
    return os.path.join(
        GetCacheGamingRootDir(),
        config.Supercategory.SETUP.val())

# Get cache gaming setup dir
def GetCacheGamingSetupDir(game_category, game_subcategory, game_name):
    return os.path.join(
        GetCacheGamingSetupRootDir(),
        game_category.val(),
        game_subcategory.val(),
        game_name)
