# Imports
import os, os.path
import sys

# Local imports
import config
import system
import release
import programs
import toolbase

# Config files
config_files = {}

# Get libs
def GetLibs(key):
    lib_files = []
    lib_root = programs.GetLibraryInstallDir("GoldbergEmu", "lib")
    for potential_file in system.BuildFileList(lib_root):
        for lib_file in programs.GetToolConfigValue("GoldbergEmu", key):
            if potential_file.endswith(lib_file):
                lib_files.append(potential_file)
    return lib_files

# Get 32-bit libs
def GetLibs32():
    return GetLibs("lib32")

# Get 64-bit libs
def GetLibs64():
    return GetLibs("lib64")

# Generate base path
def GenerateBasePath(prefix_dir):
    return os.path.join(prefix_dir, "AppData", "Roaming", "Goldberg SteamEmu Saves")

# Generate username file path
def GenerateUserNameFile(prefix_dir):
    return os.path.join(GenerateBasePath(prefix_dir), "settings", "account_name.txt")

# Generate userid file path
def GenerateUserIDFile(prefix_dir):
    return os.path.join(GenerateBasePath(prefix_dir), "settings", "user_steam_id.txt")

# Convert from native path
def ConvertFromNativePath(path, user_id):
    src_path = os.path.join(config.computer_folder_store, config.StoreType.STEAM.value, "userdata", user_id)
    dest_path = os.path.join(config.computer_folder_appdata, "Roaming", "Goldberg SteamEmu Saves")
    return path.replace(src_path, dest_path)

# Convert to native path
def ConvertToNativePath(path, user_id):
    src_path = os.path.join(config.computer_folder_appdata, "Roaming", "Goldberg SteamEmu Saves")
    dest_path = os.path.join(config.computer_folder_store, config.StoreType.STEAM.value, "userdata", user_id)
    return path.replace(src_path, dest_path)

# Setup user files
def SetupUserFiles(
    prefix_dir,
    user_name,
    user_id,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create username file
    success = system.TouchFile(
        src = GenerateUserNameFile(prefix_dir),
        contents = "%s\n" % user_name,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Create userid file
    success = system.TouchFile(
        src = GenerateUserIDFile(prefix_dir),
        contents = "%s\n" % user_id,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Must have succeeded
    return True

# Convert to native save
def ConvertToNativeSave(
    save_dir,
    user_id,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get relative paths
    roaming_path = os.path.join(config.SaveType.GENERAL.value, config.computer_folder_appdata, "Roaming")
    search_path = os.path.join(config.SaveType.GENERAL.value, config.computer_folder_appdata, "Roaming", "Goldberg SteamEmu Saves")
    ignore_path = os.path.join(config.SaveType.GENERAL.value, config.computer_folder_appdata, "Roaming", "Goldberg SteamEmu Saves", "settings")
    replace_path = os.path.join(config.SaveType.GENERAL.value, config.computer_folder_store, config.StoreType.STEAM.value, "userdata", user_id)

    # Move save files
    for save_file in system.BuildFileList(save_dir):
        if search_path in save_file and ignore_path not in save_file:
            success = system.SmartMove(
                src = save_file,
                dest = save_file.replace(search_path, replace_path),
                show_progress = True,
                skip_existing = False,
                skip_identical = False,
                case_sensitive_paths = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            at_least_one_move = success
            if not success:
                return False

    # Clean search path
    full_search_path = os.path.join(save_dir, search_path)
    success = system.RemoveDirectory(
        dir = full_search_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Clean roaming dir
    full_roaming_path = os.path.join(save_dir, roaming_path)
    if not system.DoesDirectoryContainFiles(full_roaming_path):
        success = system.RemoveDirectory(
            dir = full_roaming_path,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

    # Must be successful
    return True

# GoldbergEmu tool
class GoldbergEmu(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "GoldbergEmu"

    # Get config
    def GetConfig(self):
        return {
            "GoldbergEmu": {
                "lib32": [
                    "steam_api.dll"
                ],
                "lib64": [
                    "steam_api64.dll"
                ]
            }
        }

    # Setup
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Download library
        if programs.ShouldLibraryBeInstalled("GoldbergEmu"):
            success = release.DownloadGeneralRelease(
                archive_url = "https://gitlab.com/Mr_Goldberg/goldberg_emulator/-/jobs/4247811310/artifacts/download",
                install_name = "GoldbergEmu",
                install_dir = programs.GetLibraryInstallDir("GoldbergEmu", "lib"),
                backups_dir = programs.GetLibraryBackupDir("GoldbergEmu", "lib"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup GoldbergEmu")

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup library
        if programs.ShouldLibraryBeInstalled("GoldbergEmu"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetLibraryBackupDir("GoldbergEmu", "lib"),
                install_name = "GoldbergEmu",
                install_dir = programs.GetLibraryInstallDir("GoldbergEmu", "lib"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup GoldbergEmu")
