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
    return GetHomeDirectory()

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
    if source_type == config.source_type_remote:
        return GetRemoteLockerRootDir()
    else:
        return GetLocalLockerRootDir()

# Get locker development root dir
def GetLockerDevelopmentRootDir(source_type = None):
    return os.path.join(GetLockerRootDir(source_type), config.locker_type_development)

# Get locker gaming root dir
def GetLockerGamingRootDir(source_type = None):
    return os.path.join(GetLockerRootDir(source_type), config.locker_type_gaming)

# Get locker music root dir
def GetLockerMusicRootDir(source_type = None):
    return os.path.join(GetLockerRootDir(source_type), config.locker_type_music)

# Get locker photos root dir
def GetLockerPhotosRootDir(source_type = None):
    return os.path.join(GetLockerRootDir(source_type), config.locker_type_photos)

# Get locker programs root dir
def GetLockerProgramsRootDir(source_type = None):
    return os.path.join(GetLockerRootDir(source_type), config.locker_type_programs)

# Get locker programs tools root dir
def GetLockerProgramsToolsRootDir(source_type = None):
    return os.path.join(GetLockerProgramsRootDir(source_type), "Tools")

# Get locker gaming assets root dir
def GetLockerGamingAssetsRootDir(source_type = None):
    return os.path.join(GetLockerGamingRootDir(source_type), config.game_supercategory_assets)

# Get locker gaming emulators root dir
def GetLockerGamingEmulatorsRootDir(source_type = None):
    return os.path.join(GetLockerGamingRootDir(source_type), config.game_supercategory_emulators)

# Get locker gaming roms root dir
def GetLockerGamingRomsRootDir(source_type = None):
    return os.path.join(GetLockerGamingRootDir(source_type), config.game_supercategory_roms)

# Get locker gaming dlc root dir
def GetLockerGamingDLCRootDir(source_type = None):
    return os.path.join(GetLockerGamingRootDir(source_type), config.game_supercategory_dlc)

# Get locker gaming update root dir
def GetLockerGamingUpdateRootDir(source_type = None):
    return os.path.join(GetLockerGamingRootDir(source_type), config.game_supercategory_updates)

# Get locker gaming tags root dir
def GetLockerGamingTagsRootDir(source_type = None):
    return os.path.join(GetLockerGamingRootDir(source_type), config.game_supercategory_tags)

# Get locker gaming saves root dir
def GetLockerGamingSavesRootDir(source_type = None):
    return os.path.join(GetLockerGamingRootDir(source_type), config.game_supercategory_saves)

# Get locker gaming supercategory root dir
def GetLockerGamingSupercategoryRootDir(supercategory, source_type = None):
    if supercategory == config.game_supercategory_assets:
        return GetLockerGamingAssetsRootDir(source_type)
    elif supercategory == config.game_supercategory_emulators:
        return GetLockerGamingEmulatorsRootDir(source_type)
    elif supercategory == config.game_supercategory_roms:
        return GetLockerGamingRomsRootDir(source_type)
    elif supercategory == config.game_supercategory_dlc:
        return GetLockerGamingDLCRootDir(source_type)
    elif supercategory == config.game_supercategory_updates:
        return GetLockerGamingUpdateRootDir(source_type)
    elif supercategory == config.game_supercategory_tags:
        return GetLockerGamingTagsRootDir(source_type)
    elif supercategory == config.game_supercategory_saves:
        return GetLockerGamingSavesRootDir(source_type)
    return None

# Get locker development archives root dir
def GetLockerDevelopmentArchivesRootDir(source_type = None):
    return os.path.join(GetLockerDevelopmentRootDir(source_type), "Archive")

# Get locker gaming asset dir
def GetLockerGamingAssetDir(game_category, game_subcategory, asset_type, source_type = None):
    return os.path.join(GetLockerGamingAssetsRootDir(source_type), game_category, game_subcategory, asset_type)

# Get locker gaming asset file
def GetLockerGamingAssetFile(game_category, game_subcategory, game_name, asset_type, source_type = None):
    asset_file = "%s%s" % (game_name, config.asset_type_extensions[asset_type])
    return os.path.join(GetLockerGamingAssetsRootDir(source_type), game_category, game_subcategory, asset_type, asset_file)

# Get locker gaming emulator binaries dir
def GetLockerGamingEmulatorBinariesDir(emu_name, emu_platform, source_type = None):
    return os.path.join(GetLockerGamingEmulatorsRootDir(source_type), emu_name, "Binaries", emu_platform)

# Get locker gaming emulator setup dir
def GetLockerGamingEmulatorSetupDir(emu_name, source_type = None):
    return os.path.join(GetLockerGamingEmulatorsRootDir(source_type), emu_name, "Setup")

# Get locker gaming rom dir offset
def GetLockerGamingRomDirOffset(rom_category, rom_subcategory, rom_name):
    rom_platform = gameinfo.DeriveGamePlatformFromCategories(rom_category, rom_subcategory)
    rom_name_path = gameinfo.DeriveGameNamePathFromName(rom_name, rom_platform)
    return os.path.join(rom_category, rom_subcategory, rom_name_path)

# Get locker gaming rom dir
def GetLockerGamingRomDir(rom_category, rom_subcategory, rom_name, source_type = None):
    return os.path.join(GetLockerGamingRomsRootDir(source_type), GetLockerGamingRomDirOffset(rom_category, rom_subcategory, rom_name))

# Get locker gaming save dir
def GetLockerGamingSaveDir(game_category, game_subcategory, game_name, source_type = None):
    game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)
    game_name_path = gameinfo.DeriveGameNamePathFromName(game_name, game_platform)
    return os.path.join(GetLockerGamingSavesRootDir(source_type), game_category, game_subcategory, game_name_path)

# Get locker program tool dir
def GetLockerProgramToolDir(tool_name, tool_platform = None, source_type = None):
    if tool_platform:
        return os.path.join(GetLockerProgramsToolsRootDir(source_type), tool_name, tool_platform)
    else:
        return os.path.join(GetLockerProgramsToolsRootDir(source_type), tool_name)

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
    return os.path.join(GetPegasusMetadataRootDir(), config.game_supercategory_roms, game_category, game_subcategory, "metadata.pegasus.txt")

# Get pegasus metadata asset dir
def GetPegasusMetadataAssetDir(game_category, game_subcategory, asset_type):
    return os.path.join(GetPegasusMetadataRootDir(), config.game_supercategory_roms, game_category, game_subcategory, asset_type)

# Get metadata file
def GetMetadataFile(game_category, game_subcategory, metadata_format = config.metadata_format_type_pegasus):
    if metadata_format == config.metadata_format_type_pegasus:
        return GetPegasusMetadataFile(game_category, game_subcategory)
    return None

# Check if file is a metadata file
def IsMetadataFile(metadata_file):
    return metadata_file.endswith("metadata.pegasus.txt")

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

# Get json rom metadata dir
def GetJsonRomMetadataDir(game_category, game_subcategory):
    return os.path.join(GetJsonRomsMetadataRootDir(), game_category, game_subcategory)

# Get json rom metadata file
def GetJsonRomMetadataFile(game_category, game_subcategory, game_name):
    game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)
    game_name_path = gameinfo.DeriveGameNamePathFromName(game_name, game_platform)
    return os.path.join(GetJsonRomsMetadataRootDir(), game_category, game_subcategory, game_name_path, game_name + ".json")

# Get json rom metadata ignore file
def GetJsonRomMetadataIgnoreFile(game_category, game_subcategory):
    return os.path.join(GetJsonRomMetadataDir(game_category, game_subcategory), "ignores.json")

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
    return os.path.join(GetCacheRootDir(), config.locker_type_gaming)

# Get cache gaming roms root dir
def GetCacheGamingRomsRootDir():
    return os.path.join(GetCacheGamingRootDir(), config.game_supercategory_roms)

# Get cache gaming rom dir
def GetCacheGamingRomDir(rom_category, rom_subcategory, rom_name):
    return os.path.join(GetCacheGamingRomsRootDir(), rom_category, rom_subcategory, rom_name)

# Get cache gaming install root dir
def GetCacheGamingInstallsRootDir():
    return os.path.join(GetCacheGamingRootDir(), config.game_supercategory_installs)

# Get cache gaming install dir
def GetCacheGamingInstallDir(rom_category, rom_subcategory, rom_name):
    rom_platform = gameinfo.DeriveGamePlatformFromCategories(rom_category, rom_subcategory)
    rom_name_path = gameinfo.DeriveGameNamePathFromName(rom_name, rom_platform)
    return os.path.join(GetCacheGamingInstallsRootDir(), rom_category, rom_subcategory, rom_name_path)

# Get cache gaming saves root dir
def GetCacheGamingSavesRootDir():
    return os.path.join(GetCacheGamingRootDir(), config.game_supercategory_saves)

# Get cache gaming save dir
def GetCacheGamingSaveDir(rom_category, rom_subcategory, rom_name, rom_subname = None):
    if rom_subname:
        return os.path.join(GetCacheGamingSavesRootDir(), rom_category, rom_subcategory, rom_name, rom_subname)
    else:
        return os.path.join(GetCacheGamingSavesRootDir(), rom_category, rom_subcategory, rom_name)

# Get cache gaming setup root dir
def GetCacheGamingSetupRootDir():
    return os.path.join(GetCacheGamingRootDir(), config.game_supercategory_setup)

# Get cache gaming setup dir
def GetCacheGamingSetupDir(rom_category, rom_subcategory, rom_name):
    return os.path.join(GetCacheGamingSetupRootDir(), rom_category, rom_subcategory, rom_name)
