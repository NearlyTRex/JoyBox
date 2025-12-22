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
def check_requirements():

    # Check python version
    if sys.version_info < config.minimum_python_version:
        logger.log_error("Minimum required python version is %s.%s.%s" % config.minimum_python_version)
        logger.log_error("Please upgrade your python version")
        system.quit_program()

    # Check operating system
    is_windows = environment.is_windows_platform()
    is_linux = environment.is_linux_platform()
    if is_windows == False and is_linux == False:
        logger.log_error("Only windows and linux are supported right now", quit_program = True)

    # Check symlink support
    if not environment.are_symlinks_supported():
        logger.log_error("Symlinks are required, please enable them for your system", quit_program = True)

    # Check ini file
    if not ini.IsIniPresent():
        logger.log_error("Ini file not found, please run setup first", quit_program = True)

# Setup packages
def setup_packages(
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
            install_dir = programs.get_library_install_dir(package_name)
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
def setup_tools(
    offline = False,
    configure = False,
    clean = False,
    force = False,
    packages = None,
    setup_params = None):
    return setup_packages(
        package_list = programs.get_tools(),
        package_type = "tool",
        root_dir = environment.get_tools_root_dir(),
        offline = offline,
        configure = configure,
        clean = clean,
        force = force,
        packages = packages,
        setup_params = setup_params)

# Setup emulators
def setup_emulators(
    offline = False,
    configure = False,
    clean = False,
    force = False,
    packages = None,
    setup_params = None):
    return setup_packages(
        package_list = programs.get_emulators(),
        package_type = "emulator",
        root_dir = environment.get_emulators_root_dir(),
        offline = offline,
        configure = configure,
        clean = clean,
        force = force,
        packages = packages,
        setup_params = setup_params)

# Setup assets
def setup_assets(verbose = False, pretend_run = False, exit_on_failure = False):
    for game_category in config.Category.members():
        for game_subcategory in config.subcategory_map[game_category]:
            logger.log_info("Creating asset symlinks for %s - %s ..." % (game_category, game_subcategory))
            for asset_type in config.AssetType.members():

                # Get directories
                source_dir = environment.get_locker_gaming_asset_dir(game_category, game_subcategory, asset_type)
                dest_dir = environment.get_game_pegasus_metadata_asset_dir(game_category, game_subcategory, asset_type)
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
