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
        system.LogErrorAndQuit("Only windows and linux are supported right now")

    # Check symlink support
    if not environment.AreSymlinksSupported():
        system.LogErrorAndQuit("Symlinks are required, please enable them for your system")

    # Check ini file
    if not ini.IsIniPresent():
        system.LogErrorAndQuit("Ini file not found, please run setup first")

# Setup tools
def SetupTools(offline = False, verbose = False, pretend_run = False, exit_on_failure = False):
    for tool in programs.GetTools():
        system.LogInfo("Installing tool %s ..." % tool.GetName())
        if offline:
            tool.SetupOffline(
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        else:
            tool.Setup(
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        tool.Configure(
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Setup emulators
def SetupEmulators(offline = False, configure = False, verbose = False, pretend_run = False, exit_on_failure = False):
    for emulator in programs.GetEmulators():
        system.LogInfo("Installing emulator %s ..." % emulator.GetName())
        if offline:
            emulator.SetupOffline(
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        else:
            emulator.Setup(
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        if configure:
            emulator.Configure(
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

# Setup assets
def SetupAssets(verbose = False, pretend_run = False, exit_on_failure = False):

    # Create asset symlinks
    for game_category in config.game_categories:
        for game_subcategory in config.game_subcategories[game_category]:
            system.LogInfo("Creating asset symlinks for %s - %s ..." % (game_category, game_subcategory))
            for asset_type in config.AssetType.members():

                # Get directories
                source_dir = environment.GetLockerGamingAssetDir(game_category, game_subcategory, asset_type)
                dest_dir = environment.GetPegasusMetadataAssetDir(game_category, game_subcategory, asset_type)
                dest_parent_dir = system.GetDirectoryParent(dest_dir)

                # Create source dir if it doesn't exist
                if not system.DoesPathExist(source_dir):
                    system.MakeDirectory(
                        dir = source_dir,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)

                # Create dest parent dir if it doesn't exist
                if not system.DoesPathExist(dest_parent_dir):
                    system.MakeDirectory(
                        dir = dest_parent_dir,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)

                # Remove existing symlink
                system.RemoveSymlink(
                    symlink = dest_dir,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)

                # Make new symlink
                system.CreateSymlink(
                    src = source_dir,
                    dest = dest_dir,
                    cwd = dest_parent_dir,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
