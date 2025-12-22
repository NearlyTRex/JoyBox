# Imports
import os, os.path
import sys

# Local imports
import config
import environment
import fileops
import system
import logger
import paths
import programs
import ini

# Check requirements
def CheckRequirements():

    # Check python version
    if sys.version_info < config.minimum_python_version:
        logger.log_error("Minimum required python version is %s.%s.%s" % config.minimum_python_version)
        logger.log_error("Please upgrade your python version")
        system.quit_program()

    # Check operating system
    is_windows = environment.IsWindowsPlatform()
    is_linux = environment.IsLinuxPlatform()
    if is_windows == False and is_linux == False:
        logger.log_error("Only windows and linux are supported right now", quit_program = True)

    # Check symlink support
    if not environment.AreSymlinksSupported():
        logger.log_error("Symlinks are required, please enable them for your system", quit_program = True)

    # Check ini file
    if not ini.IsIniPresent():
        logger.log_error("Ini file not found, please run setup first", quit_program = True)

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
    setup_params = None):

    # Create default setup params if not provided
    if not setup_params:
        setup_params = config.SetupParams()

    # Clean root directory
    if clean:
        if paths.does_path_exist(root_dir):
            logger.log_info("Cleaning %s directory %s ..." % (package_type, root_dir))
            fileops.remove_directory(
                src = root_dir,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)

    # Install packages
    for package in package_list:
        package_name = package.GetName()

        # Skip if not in package list (when specified)
        if packages is not None and package_name not in packages:
            continue

        # Force reinstall by cleaning the install directory
        if force:
            install_dir = programs.GetLibraryInstallDir(package_name)
            if paths.does_path_exist(install_dir):
                logger.log_info("Forcing rebuild of %s (removing %s) ..." % (package_name, install_dir))
                fileops.remove_directory(
                    src = install_dir,
                    verbose = setup_params.verbose,
                    pretend_run = setup_params.pretend_run,
                    exit_on_failure = setup_params.exit_on_failure)

        # Install package
        logger.log_info("Installing %s %s ..." % (package_type, package_name))
        success = False
        if offline:
            success = package.SetupOffline(setup_params = setup_params)
        else:
            success = package.Setup(setup_params = setup_params)
        if not success:
            return False
        if configure:
            success = package.Configure(setup_params = setup_params)
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
    setup_params = None):
    return SetupPackages(
        package_list = programs.GetTools(),
        package_type = "tool",
        root_dir = environment.GetToolsRootDir(),
        offline = offline,
        configure = configure,
        clean = clean,
        force = force,
        packages = packages,
        setup_params = setup_params)

# Setup emulators
def SetupEmulators(
    offline = False,
    configure = False,
    clean = False,
    force = False,
    packages = None,
    setup_params = None):
    return SetupPackages(
        package_list = programs.GetEmulators(),
        package_type = "emulator",
        root_dir = environment.GetEmulatorsRootDir(),
        offline = offline,
        configure = configure,
        clean = clean,
        force = force,
        packages = packages,
        setup_params = setup_params)

# Setup assets
def SetupAssets(verbose = False, pretend_run = False, exit_on_failure = False):
    for game_category in config.Category.members():
        for game_subcategory in config.subcategory_map[game_category]:
            logger.log_info("Creating asset symlinks for %s - %s ..." % (game_category, game_subcategory))
            for asset_type in config.AssetType.members():

                # Get directories
                source_dir = environment.GetLockerGamingAssetDir(game_category, game_subcategory, asset_type)
                dest_dir = environment.GetGamePegasusMetadataAssetDir(game_category, game_subcategory, asset_type)
                dest_parent_dir = paths.get_directory_parent(dest_dir)

                # Create source dir if it doesn't exist
                if not paths.does_path_exist(source_dir):
                    fileops.make_directory(
                        src = source_dir,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)

                # Make new symlink
                success = fileops.create_symlink(
                    src = source_dir,
                    dest = dest_dir,
                    cwd = dest_parent_dir,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
                if not success:
                    return False
    return True
