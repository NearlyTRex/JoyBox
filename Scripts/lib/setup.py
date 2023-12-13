# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.dirname(__file__))
sys.path.append(lib_folder)
import config
import sandbox
import environment
import system
import programs
import metadata
import python
import packages

# Check requirements
def CheckRequirements():

    # Check python version
    if sys.version_info < config.python.minimum_python_version:
        print("Minimum required python version is %s.%s.%s" % config.python.minimum_python_version)
        print("Please upgrade your python version")
        sys.exit(1)

    # Check operating system
    is_windows = environment.IsWindowsPlatform()
    is_linux = environment.IsLinuxPlatform()
    if is_windows == False and is_linux == False:
        print("Only windows and linux are supported right now")
        sys.exit(1)

    # Check symlink support
    if not environment.AreSymlinksSupported():
        print("Symlinks are required, please enable them for your system")
        sys.exit(1)

    # Check wine
    has_wine = sandbox.IsWineInstalled()
    if is_linux and has_wine == False:
        print("Wine (including winetricks) is required for linux environments, please install it and make sure it is in the path")
        sys.exit(1)

    # Check sandboxie
    has_sandboxie = sandbox.IsSandboxieInstalled()
    if is_windows and has_sandboxie == False:
        print("Sandboxie is required for windows environments, please install it and make sure it is in the path")
        sys.exit(1)

# Setup environment
def SetupEnvironment(verbose = False, exit_on_failure = False):

    # Setup python environment
    python.SetupPythonEnvironment(verbose = verbose, exit_on_failure = exit_on_failure)

    # Get required python modules
    required_modules = config.python.required_python_modules_all
    if environment.IsWindowsPlatform():
        required_modules += config.python.required_python_modules_windows
    elif environment.IsLinuxPlatform():
        required_modules += config.python.required_python_modules_linux

    # Get required system packages
    required_packages = config.packages.required_system_packages_all
    if environment.IsWindowsPlatform():
        required_packages += config.packages.required_system_packages_windows
    elif environment.IsLinuxPlatform():
        required_packages += config.packages.required_system_packages_linux

    # Install required python modules
    for module in required_modules:
        python.InstallPythonModule(
            module = module,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Install required system packages
    for package in required_packages:
        packages.InstallSystemPackage(
            package = package,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Setup required tools
    for tool in programs.GetTools():
        tool.Download(
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        tool.Setup(
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Setup required emulators
    for emulator in programs.GetEmulators():
        emulator.Download(
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        emulator.Setup(
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Loop through categories and asset types
    for game_category in metadata.GetMetadataCategories():
        for game_subcategory in metadata.GetMetadataSubcategories(game_category):
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
