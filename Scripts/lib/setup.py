# Imports
import os, os.path
import sys

# Local imports
import config
import environment
import system
import programs
import ini

# Check requirements
def CheckRequirements():

    # Check python version
    if sys.version_info < config.minimum_python_version:
        system.LogError("Minimum required python version is %s.%s.%s" % config.minimum_python_version)
        system.LogError("Please upgrade your python version")
        system.QuitProgram()

    # Check operating system
    is_windows = environment.IsWindowsPlatform()
    is_linux = environment.IsLinuxPlatform()
    if is_windows == False and is_linux == False:
        system.LogError("Only windows and linux are supported right now", quit_program = True)

    # Check symlink support
    if not environment.AreSymlinksSupported():
        system.LogError("Symlinks are required, please enable them for your system", quit_program = True)

    # Check ini file
    if not ini.IsIniPresent():
        system.LogError("Ini file not found, please run setup first", quit_program = True)

# Setup tools
def SetupTools(offline = False, configure = False, verbose = False, pretend_run = False, exit_on_failure = False):
    for tool in programs.GetTools():
        system.LogInfo("Installing tool %s ..." % tool.GetName())
        success = False
        if offline:
            success = tool.SetupOffline(
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        else:
            success = tool.Setup(
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        if not success:
            return False
        if not configure:
            success = tool.Configure(
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return False
    return True

# Setup emulators
def SetupEmulators(offline = False, configure = False, verbose = False, pretend_run = False, exit_on_failure = False):
    for emulator in programs.GetEmulators():
        system.LogInfo("Installing emulator %s ..." % emulator.GetName())
        success = False
        if offline:
            success = emulator.SetupOffline(
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        else:
            success = emulator.Setup(
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        if not success:
            return False
        if configure:
            success = emulator.Configure(
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return False
    return True

# Setup assets
def SetupAssets(verbose = False, pretend_run = False, exit_on_failure = False):
    for game_category in config.Category.members():
        for game_subcategory in config.subcategory_map[game_category]:
            system.LogInfo("Creating asset symlinks for %s - %s ..." % (game_category, game_subcategory))
            for asset_type in config.AssetType.members():

                # Get directories
                source_dir = environment.GetLockerGamingAssetDir(game_category, game_subcategory, asset_type)
                dest_dir = environment.GetPegasusMetadataAssetDir(game_category, game_subcategory, asset_type)
                dest_parent_dir = system.GetDirectoryParent(dest_dir)

                # Create source dir if it doesn't exist
                if not system.DoesPathExist(source_dir):
                    system.MakeDirectory(
                        src = source_dir,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)

                # Make new symlink
                success = system.CreateSymlink(
                    src = source_dir,
                    dest = dest_dir,
                    cwd = dest_parent_dir,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
                if not success:
                    return False
    return True
