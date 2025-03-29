# Imports
import os
import sys

# Local imports
import config
import system
import environment
import metadata
import programs
import gameinfo
import saves
import transform
import platforms
import locker
import stores
import gui

###########################################################

# Check if store game is installed
def IsStoreGameInstalled(game_info):

    # Check game info
    if not game_info or not game_info.is_valid():
        return False

    # Get store
    store_obj = stores.GetStoreByPlatform(game_info.get_platform())
    if not store_obj:
        return False

    # Check store install
    store_key = game_info.get_main_store_key()
    store_identifier_key = store_obj.GetInstallIdentifierKey()
    store_identifier = game_info.get_subvalue(store_key, store_identifier_key)
    return store_obj.IsInstalled(store_identifier)

# Install store game
def InstallStoreGame(
    game_info,
    source_type,
    keep_setup_files = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check game info
    if not game_info or not game_info.is_valid():
        return False

    # Get store
    store_obj = stores.GetStoreByPlatform(game_info.get_platform())
    if not store_obj:
        return False

    # Install game
    store_key = game_info.get_main_store_key()
    store_identifier_key = store_obj.GetInstallIdentifierKey()
    store_identifier = game_info.get_subvalue(store_key, store_identifier_key)
    return store_obj.Install(
        identifier = store_identifier,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Uninstall store game
def UninstallStoreGame(
    game_info,
    source_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check game info
    if not game_info or not game_info.is_valid():
        return False

    # Get store
    store_obj = stores.GetStoreByPlatform(game_info.get_platform())
    if not store_obj:
        return False

    # Uninstall game
    store_key = game_info.get_main_store_key()
    store_identifier_key = store_obj.GetInstallIdentifierKey()
    store_identifier = game_info.get_subvalue(store_key, store_identifier_key)
    return store_obj.Uninstall(
        identifier = store_identifier,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Launch store game
def LaunchStoreGame(
    game_info,
    source_type,
    capture_type = None,
    fullscreen = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check game info
    if not game_info or not game_info.is_valid() or not game_info.is_playable():
        return False

    # Get store
    store_obj = stores.GetStoreByPlatform(game_info.get_platform())
    if not store_obj:
        return False

    # Launch game
    store_key = game_info.get_main_store_key()
    store_identifier_key = store_obj.GetInstallIdentifierKey()
    store_identifier = game_info.get_subvalue(store_key, store_identifier_key)
    return store_obj.Launch(
        identifier = store_identifier,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

###########################################################

# Check if local game is installed
def IsLocalGameInstalled(game_info):
    cache_dir = game_info.get_local_cache_dir()
    return system.DoesDirectoryContainFiles(cache_dir)

# Install local game
def InstallLocalGame(
    game_info,
    source_type,
    keep_setup_files = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get game info
    game_name = game_info.get_name()
    game_platform = game_info.get_platform()
    game_artwork = game_info.get_boxfront_asset()
    game_remote_rom_dir = game_info.get_remote_rom_dir()

    # Check if already installed
    if IsLocalGameInstalled(game_info):
        return True

    # Check if source files are available
    if not locker.DoesRemotePathContainFiles(game_remote_rom_dir):
        gui.DisplayErrorPopup(
            title_text = "Source files unavailable",
            message_text = "Source files are not available\n%s\n%s" % (game_name, game_platform))
        return False

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        return False

    # Download files
    success = locker.DownloadAndDecryptPath(
        src = game_remote_rom_dir,
        dest = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Check if transformation is required
    if platforms.IsTransformPlatform(game_platform):

        # Install transformed game
        def InstallTransformedGame():
            return InstallLocalTransformedGame(
                game_info = game_info,
                source_dir = tmp_dir_result,
                keep_setup_files = keep_setup_files,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        gui.DisplayLoadingWindow(
            title_text = "Installing to cache",
            message_text = "Transforming and adding game to cache\n%s\n%s" % (game_name, game_platform),
            failure_text = "Unable to install game to cache",
            image_file = game_artwork,
            run_func = InstallTransformedGame)
    else:

        # Install game
        def InstallGame():
            return InstallLocalUntransformedGame(
                game_info = game_info,
                source_dir = tmp_dir_result,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        gui.DisplayLoadingWindow(
            title_text = "Installing to cache",
            message_text = "Adding game to cache\n%s\n%s" % (game_name, game_platform),
            failure_text = "Unable to install game to cache",
            image_file = game_artwork,
            run_func = InstallGame)

    # Delete temporary directory
    system.RemoveDirectory(
        src = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check if game is now installed
    if not IsLocalGameInstalled(game_info):
        gui.DisplayErrorPopup(
            title_text = "Failed to cache game",
            message_text = "Game could not be cached\n%s\n%s" % (game_name, game_platform))
    return True

# Install local untransformed game
def InstallLocalUntransformedGame(
    game_info,
    source_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Copy game files
    success = system.CopyContents(
        src = source_dir,
        dest = game_info.get_local_cache_dir(),
        show_progress = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Return result
    return IsLocalGameInstalled(game_info)

# Add local transformed game
def InstallLocalTransformedGame(
    game_info,
    source_dir,
    keep_setup_files = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        return False

    # Transform game file
    transform_success, transform_result = transform.TransformGameFile(
        game_info = game_info,
        source_dir = source_dir,
        output_dir = tmp_dir_result,
        keep_setup_files = keep_setup_files,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not transform_success:
        system.LogError(transform_result)
        return False

    # Add to cache
    InstallLocalUntransformedGame(
        game_info = game_info,
        source_dir = system.GetFilenameDirectory(transform_result),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Delete temporary directory
    system.RemoveDirectory(
        src = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Return result
    return IsLocalGameInstalled(game_info)

# Uninstall local game
def UninstallLocalGame(
    game_info,
    source_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check if already installed
    if not IsLocalGameInstalled(game_info):
        return True

    # Remove local cache
    success = system.RemoveDirectory(
        src = game_info.get_local_cache_dir(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Remove remote cache
    success = system.RemoveDirectory(
        src = game_info.get_remote_cache_dir(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Launch local game
def LaunchLocalGame(
    game_info,
    source_type,
    capture_type = None,
    fullscreen = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get game info
    game_name = game_info.get_name()
    game_category = game_info.get_category()
    game_subcategory = game_info.get_subcategory()
    game_platform = game_info.get_platform()
    game_save_dir = game_info.get_save_dir()

    # Install local game
    success = InstallLocalGame(
        game_info = game_info,
        source_type = source_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Get launcher
    game_launcher = None
    for emulator in programs.GetEmulators():
        if game_platform in emulator.GetPlatforms():
            game_launcher = emulator
            break

    # Check game launcher
    if not game_launcher:
        gui.DisplayErrorPopup(
            title_text = "Launcher not found",
            message_text = "Launcher for game '%s' in platform '%s' could not be found" % (game_name, game_platform))
        return False

    # Get game launcher info
    game_launcher_config_file = game_launcher.GetConfigFile()
    game_launcher_save_dir = game_launcher.GetSaveDir(game_platform)
    game_launcher_setup_dir = game_launcher.GetSetupDir()

    # Unpack save if possible
    if saves.CanSaveBeUnpacked(game_category, game_subcategory, game_name):
        success = saves.UnpackSave(
            game_category = game_category,
            game_subcategory = game_subcategory,
            game_name = game_name,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

    # Setup launcher save directory
    if game_launcher_save_dir:
        success = system.CreateSymlink(
            src = game_save_dir,
            dest = game_launcher_save_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

    # Setup launcher config file
    if game_launcher_config_file:
        system.ReplaceStringsInFile(
            src = game_launcher_config_file,
            replacements = [
                {"from": config.token_emulator_setup_root, "to": game_launcher_setup_dir},
                {"from": config.token_game_save_dir, "to": game_save_dir}
            ],
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Launch game
    success = game_launcher.Launch(
        game_info = game_info,
        capture_type = capture_type,
        fullscreen = fullscreen,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Revert launcher config file
    if game_launcher_config_file:
        system.ReplaceStringsInFile(
            src = game_launcher_config_file,
            replacements = [
                {"from": game_launcher_setup_dir, "to": config.token_emulator_setup_root},
                {"from": game_save_dir, "to": config.token_game_save_dir}
            ],
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Revert launcher save directory
    if game_launcher_save_dir:
        success = system.RemoveObject(
            obj = game_launcher_save_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
        success = system.MakeDirectory(
            src = game_launcher_save_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

    # Pack save
    success = saves.PackSave(
        game_category = game_category,
        game_subcategory = game_subcategory,
        game_name = game_name,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

###########################################################

# Check if game is installed
def IsGameInstalled(game_info):
    if stores.CanHandleInstalling(game_info.get_platform()):
        return IsStoreGameInstalled(game_info)
    else:
        return IsLocalGameInstalled(game_info)

# Install game
def InstallGame(
    game_info,
    source_type,
    keep_setup_files = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if stores.CanHandleInstalling(game_info.get_platform()):
        return InstallStoreGame(
            game_info = game_info,
            source_type = source_type,
            keep_setup_files = keep_setup_files,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    else:
        return InstallLocalGame(
            game_info = game_info,
            source_type = source_type,
            keep_setup_files = keep_setup_files,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Uninstall game
def UninstallGame(
    game_info,
    source_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if stores.CanHandleInstalling(game_info.get_platform()):
        return UninstallStoreGame(
            game_info = game_info,
            source_type = source_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    else:
        return UninstallLocalGame(
            game_info = game_info,
            source_type = source_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Launch local game
def LaunchGame(
    game_info,
    source_type,
    capture_type = None,
    fullscreen = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if stores.CanHandleLaunching(game_info.get_platform()):
        return LaunchStoreGame(
            game_info = game_info,
            source_type = source_type,
            capture_type = capture_type,
            fullscreen = fullscreen,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    else:
        return LaunchLocalGame(
            game_info = game_info,
            source_type = source_type,
            capture_type = capture_type,
            fullscreen = fullscreen,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

###########################################################
