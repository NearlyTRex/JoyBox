# Imports
import os, os.path
import sys
import time
import signal
import ntpath

# Local imports
import config
import command
import system
import metadata
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

# Run as root if necessary
def RunAsRootIfNecessary(func):
    if callable(func):
        func()

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
# Tools
###########################################################

# Get tools root dir
def GetToolsRootDir():
    tools_dir = ini.GetIniPathValue("UserData.Dirs", "tools_dir")
    system.AssertPathExists(tools_dir, "tools_dir")
    return tools_dir

###########################################################
# Emulators
###########################################################

# Get emulators root dir
def GetEmulatorsRootDir():
    emulators_dir = ini.GetIniPathValue("UserData.Dirs", "emulators_dir")
    system.AssertPathExists(emulators_dir, "emulators_dir")
    return emulators_dir

###########################################################
# Sync
###########################################################

# Get sync root dir
def GetSyncRootDir():
    sync_dir = ini.GetIniPathValue("UserData.Dirs", "sync_dir")
    system.AssertPathExists(sync_dir, "sync_dir")
    return sync_dir

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
# Metadata
###########################################################

# Get metadata root dir
def GetMetadataRootDir():
    metadata_dir = ini.GetIniPathValue("UserData.Dirs", "metadata_dir")
    system.AssertPathExists(metadata_dir, "metadata_dir")
    return metadata_dir

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
# Scripts
###########################################################

# Get scripts root dir
def GetScriptsRootDir():
    scripts_dir = ini.GetIniPathValue("UserData.Dirs", "scripts_dir")
    system.AssertPathExists(scripts_dir, "scripts_dir")
    return scripts_dir

# Get scripts bin dir
def GetScriptsBinDir():
    return os.path.join(GetScriptsRootDir(), "bin")

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
# Storage
###########################################################

# Get storage root dir
def GetStorageRootDir():
    storage_dir = ini.GetIniPathValue("UserData.Dirs", "storage_dir")
    system.AssertPathExists(storage_dir, "storage_dir")
    return storage_dir

# Get gaming storage root dir
def GetGamingStorageRootDir():
    return os.path.join(GetStorageRootDir(), "Gaming")

# Get rom root dir
def GetRomRootDir():
    return os.path.join(GetGamingStorageRootDir(), config.game_supercategory_roms)

# Get rom dir
def GetRomDir(rom_category, rom_subcategory, rom_name):
    if rom_category == config.game_category_computer:
        letter = metadata.DeriveGameLetterFromName(rom_name)
        return os.path.join(GetRomRootDir(), rom_category, rom_subcategory, letter, rom_name)
    else:
        return os.path.join(GetRomRootDir(), rom_category, rom_subcategory, rom_name)

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
# Cache
###########################################################

# Get local cache root dir
def GetLocalCacheRootDir():
    local_cache_dir = ini.GetIniPathValue("UserData.Dirs", "local_cache_dir")
    system.AssertPathExists(local_cache_dir, "local_cache_dir")
    return local_cache_dir

# Get remote cache root dir
def GetRemoteCacheRootDir():
    remote_cache_dir = ini.GetIniPathValue("UserData.Dirs", "remote_cache_dir")
    system.AssertPathExists(remote_cache_dir, "remote_cache_dir")
    return remote_cache_dir

# Get gaming cache root dir
def GetGamingLocalCacheRootDir():
    return os.path.join(GetLocalCacheRootDir(), "Gaming")

# Get gaming cache root dir
def GetGamingRemoteCacheRootDir():
    return os.path.join(GetRemoteCacheRootDir(), "Gaming")

# Get cached roms root dir
def GetCachedRomsRootDir():
    return os.path.join(GetGamingLocalCacheRootDir(), config.game_supercategory_roms)

# Get install rom root dir
def GetInstallRomRootDir():
    return os.path.join(GetGamingRemoteCacheRootDir(), config.game_supercategory_installs)

# Get install rom dir
def GetInstallRomDir(rom_category, rom_subcategory, rom_name):
    if rom_category == config.game_category_computer:
        letter = metadata.DeriveGameLetterFromName(rom_name)
        return os.path.join(GetInstallRomRootDir(), rom_category, rom_subcategory, letter, rom_name)
    else:
        return os.path.join(GetInstallRomRootDir(), rom_category, rom_subcategory, rom_name)

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
