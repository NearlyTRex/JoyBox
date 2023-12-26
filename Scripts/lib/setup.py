# Imports
import os, os.path
import sys

# Local imports
import config
import environment
import system
import programs
import metadata
import ini

# Check basics
def CheckBasics():

    # Check python version
    if sys.version_info < config.minimum_python_version:
        system.LogError("Minimum required python version is %s.%s.%s" % config.minimum_python_version)
        system.LogError("Please upgrade your python version")
        sys.exit(1)

    # Check operating system
    is_windows = environment.IsWindowsPlatform()
    is_linux = environment.IsLinuxPlatform()
    if is_windows == False and is_linux == False:
        system.LogError("Only windows and linux are supported right now")
        sys.exit(1)

    # Check symlink support
    if not environment.AreSymlinksSupported():
        system.LogError("Symlinks are required, please enable them for your system")
        sys.exit(1)

# Check ini
def CheckIni():

    # Check ini file
    if not ini.IsIniPresent():
        system.LogError("Ini file not found, please run setup first")
        sys.exit(1)

# Check programs
def CheckPrograms():

    # Get required programs
    required_programs = []
    if environment.IsWinePlatform():
        required_programs += [
            "Wine",
            "WineTricks"
        ]
    elif environment.IsSandboxiePlatform():
        required_programs += [
            "Sandboxie"
        ]
    required_programs += [
        "Curl",
        "Git",
        "7-Zip",
        "Firefox"
    ]

    # Check required programs
    for required_program in required_programs:
        if not programs.IsProgramInstalled(required_program):
            system.LogError("Required program '%s' was not found, please install it")
            sys.exit(1)

# Check requirements
def CheckRequirements():
    CheckBasics()
    CheckIni()
    CheckPrograms()

# Setup environment
def SetupEnvironment(verbose = False, exit_on_failure = False):

    # Check basics
    CheckBasics()

    # Setup ini file
    system.LogInfo("Initializing ini file")
    ini.InitializeIniFile(verbose = verbose, exit_on_failure = exit_on_failure)

    # Setup tools
    for tool in programs.GetTools():
        system.LogInfo("Installing tool %s ..." % tool.GetName())
        tool.Setup(
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Setup emulators
    for emulator in programs.GetEmulators():
        system.LogInfo("Installing emulator %s ..." % emulator.GetName())
        emulator.Setup(
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Create asset symlinks
    for game_category in config.game_categories:
        for game_subcategory in config.game_subcategories[game_category]:
            system.LogInfo("Creating asset symlinks for %s - %s ..." % (game_category, game_subcategory))
            for asset_type in config.asset_types_all:

                # Get directories
                source_dir = environment.GetSyncedGameAssetDir(game_category, game_subcategory, asset_type)
                dest_dir = environment.GetPegasusMetadataAssetDir(game_category, game_subcategory, asset_type)

                # Remove existing symlink
                system.RemoveSymlink(
                    symlink = dest_dir,
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)

                # Make new symlink
                system.CreateSymlink(
                    src = source_dir,
                    dest = dest_dir,
                    cwd = system.GetDirectoryParent(dest_dir),
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)
