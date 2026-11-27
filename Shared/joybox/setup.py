# Imports
import sys

# Local imports
from joybox import emulators
from joybox import tools
from joybox import config
from joybox import environment
from joybox import fileops
from joybox import logger
from joybox import paths
from joybox import release
from joybox import settings
from joybox import platform_info, runtime

# Quit unless Python meets the minimum version, the OS is Windows or Linux, symlinks work and the ini exists
def check_requirements():

    # Check python version
    if sys.version_info < config.minimum_python_version:
        logger.log_error("Minimum required python version is %s.%s.%s" % config.minimum_python_version)
        logger.log_error("Please upgrade your python version")
        runtime.quit_program()

    # Check operating system
    is_windows = platform_info.is_windows_platform()
    is_linux = platform_info.is_linux_platform()
    if not is_windows and not is_linux:
        logger.log_error("Only windows and linux are supported right now", quit_program = True)

    # Check symlink support
    if not fileops.are_symlinks_supported():
        logger.log_error("Symlinks are required, please enable them for your system", quit_program = True)

    # Check ini file
    if not settings.is_present():
        logger.log_error("Ini file not found, please run setup first", quit_program = True)

# Install each package (or only those named), optionally online/offline, configured, cleaned or forced
# Stops with False at the first failure; warns about downloads the lockers could not back up
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
    if clean and paths.does_path_exist(root_dir):
        logger.log_info("Cleaning %s directory %s ..." % (package_type, root_dir))
        _remove_install_directory(root_dir, setup_params)

    # Install packages
    release.failed_backups.clear()
    success = _install_selected_packages(package_list, package_type, root_dir, offline, configure, force, packages, setup_params)
    if not success:
        return False

    # Report the downloads the lockers did not get, which -f backs up again once fixed
    _report_failed_backups(package_type)
    return True

# Install each package, or only those named in packages; False at the first that fails
def _install_selected_packages(package_list, package_type, root_dir, offline, configure, force, packages, setup_params):
    for package in package_list:
        package_name = package.get_name()

        # Skip if not in package list (when specified)
        if packages is not None and package_name not in packages:
            continue

        # Force reinstall by cleaning each of the package's install directories
        if force:
            _remove_package_install_dirs(package, root_dir, setup_params)

        # Install package
        logger.log_info("Installing %s %s ..." % (package_type, package_name))
        success = _install_package(package, offline, configure, setup_params)
        if not success:
            return False
    return True

# Remove a directory with the setup params' verbosity, pretend and failure settings
def _remove_install_directory(install_dir, setup_params):
    fileops.remove_directory(
        src = install_dir,
        verbose = setup_params.verbose,
        pretend_run = setup_params.pretend_run,
        exit_on_failure = setup_params.exit_on_failure)

# Remove each existing install directory of the package's programs, or its own name's when it has none
def _remove_package_install_dirs(package, root_dir, setup_params):
    package_name = package.get_name()
    for program_name in list(package.get_config()) or [package_name]:
        install_dir = paths.join_paths(root_dir, program_name)
        if paths.does_path_exist(install_dir):
            logger.log_info("Forcing rebuild of %s (removing %s) ..." % (package_name, install_dir))
            _remove_install_directory(install_dir, setup_params)

# Set the package up online or offline, then configure it when asked; False when either step fails
def _install_package(package, offline, configure, setup_params):
    success = False
    if offline:
        success = package.setup_offline(setup_params = setup_params)
    else:
        success = package.setup(setup_params = setup_params)
    if not success:
        return False
    if configure:
        return package.configure(setup_params = setup_params)
    return True

# Warn about each download this run could not back up to the lockers
def _report_failed_backups(package_type):
    if release.failed_backups:
        logger.log_warning("%d download(s) could not be backed up to the lockers:" % len(release.failed_backups))
        for backup_dest in release.failed_backups:
            logger.log_warning("  %s" % backup_dest)
        logger.log_warning("Fix the lockers, then reinstall those %ss with --force to back them up" % package_type)

# Install every tool into the tools root directory through setup_packages
def setup_tools(
    offline = False,
    configure = False,
    clean = False,
    force = False,
    packages = None,
    setup_params = None):
    return setup_packages(
        package_list = tools.get_tool_list(),
        package_type = "tool",
        root_dir = environment.get_tools_root_dir(),
        offline = offline,
        configure = configure,
        clean = clean,
        force = force,
        packages = packages,
        setup_params = setup_params)

# Install every emulator into the emulators root directory through setup_packages
def setup_emulators(
    offline = False,
    configure = False,
    clean = False,
    force = False,
    packages = None,
    setup_params = None):
    return setup_packages(
        package_list = emulators.get_emulator_list(),
        package_type = "emulator",
        root_dir = environment.get_emulators_root_dir(),
        offline = offline,
        configure = configure,
        clean = clean,
        force = force,
        packages = packages,
        setup_params = setup_params)

# Symlink each category's locker asset directories into the Pegasus metadata tree, creating missing sources
def setup_assets(verbose = False, pretend_run = False, exit_on_failure = False):
    for game_category in config.Category.members():
        for game_subcategory in config.subcategory_map[game_category]:
            logger.log_info("Creating asset symlinks for %s - %s ..." % (game_category, game_subcategory))
            success = _link_subcategory_assets(game_category, game_subcategory, verbose, pretend_run, exit_on_failure)
            if not success:
                return False
    return True

# Symlink each asset type's locker directory into the subcategory's Pegasus metadata; False at the first failure
def _link_subcategory_assets(game_category, game_subcategory, verbose, pretend_run, exit_on_failure):
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
