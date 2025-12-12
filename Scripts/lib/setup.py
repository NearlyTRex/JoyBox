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

# Setup packages
def SetupPackages(
    package_list,
    package_type,
    root_dir,
    offline = False,
    configure = False,
    clean = False,
    force = False,
    packages = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Clean root directory
    if clean:
        if system.DoesPathExist(root_dir):
            system.LogInfo("Cleaning %s directory %s ..." % (package_type, root_dir))
            system.RemoveDirectory(
                src = root_dir,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

    # Install packages
    for package in package_list:
        package_name = package.GetName()

        # Skip if not in package list (when specified)
        if packages is not None and package_name not in packages:
            continue

        # Force reinstall by cleaning the install directory
        if force:
            install_dir = programs.GetLibraryInstallDir(package_name)
            if system.DoesPathExist(install_dir):
                system.LogInfo("Forcing rebuild of %s (removing %s) ..." % (package_name, install_dir))
                system.RemoveDirectory(
                    src = install_dir,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)

        # Install package
        system.LogInfo("Installing %s %s ..." % (package_type, package_name))
        success = False
        if offline:
            success = package.SetupOffline(
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        else:
            success = package.Setup(
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        if not success:
            return False
        if configure:
            success = package.Configure(
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return False
    return True

# Setup tools
def SetupTools(
    offline = False,
    configure = False,
    clean = False,
    force = False,
    packages = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    return SetupPackages(
        package_list = programs.GetTools(),
        package_type = "tool",
        root_dir = environment.GetToolsRootDir(),
        offline = offline,
        configure = configure,
        clean = clean,
        force = force,
        packages = packages,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Setup emulators
def SetupEmulators(
    offline = False,
    configure = False,
    clean = False,
    force = False,
    packages = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    return SetupPackages(
        package_list = programs.GetEmulators(),
        package_type = "emulator",
        root_dir = environment.GetEmulatorsRootDir(),
        offline = offline,
        configure = configure,
        clean = clean,
        force = force,
        packages = packages,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Setup assets
def SetupAssets(verbose = False, pretend_run = False, exit_on_failure = False):
    for game_category in config.Category.members():
        for game_subcategory in config.subcategory_map[game_category]:
            system.LogInfo("Creating asset symlinks for %s - %s ..." % (game_category, game_subcategory))
            for asset_type in config.AssetType.members():

                # Get directories
                source_dir = environment.GetLockerGamingAssetDir(game_category, game_subcategory, asset_type)
                dest_dir = environment.GetGamePegasusMetadataAssetDir(game_category, game_subcategory, asset_type)
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
