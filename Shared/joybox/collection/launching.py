# Local imports
from joybox import emulators
from joybox import config
from joybox import fileops
from joybox import fileedits
from joybox import stores
from joybox import gui
from joybox import paths
from .installing import install_store_game
from .installing import install_local_game
from .saves import export_store_game_save
from .saves import import_local_game_save
from .saves import export_local_game_save

###########################################################

# Install the game through its store client, launch it there, then export its save to the locker
def launch_store_game(
    game_info,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check game info
    if not game_info or not game_info.is_valid() or not game_info.is_playable():
        return False

    # Install store game
    success = install_store_game(
        game_info = game_info,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Get store
    store_obj = stores.get_store_by_platform(game_info.get_platform())
    if not store_obj:
        return False

    # Check if store handles launching
    if not store_obj.can_handle_launching():
        return False

    # Get store info
    store_key = game_info.get_main_store_key()
    store_identifier_key = store_obj.get_install_identifier_key()
    store_identifier = game_info.get_subvalue(store_key, store_identifier_key)

    # Launch game
    success = store_obj.launch(
        identifier = store_identifier,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Export save
    success = export_store_game_save(
        game_info = game_info,
        locker_type = locker_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

###########################################################

# Put the tokens back in the launcher's config file and replace its save-dir symlink with an empty directory
def _revert_launcher_setup(
    game_info,
    game_launcher,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    game_launcher_config_file = game_launcher.get_config_file()
    game_launcher_save_dir = game_launcher.get_save_dir(game_info.get_platform())
    if paths.is_path_file(game_launcher_config_file):
        fileedits.replace_strings_in_file(
            src = game_launcher_config_file,
            replacements = [
                {"from": game_launcher.get_setup_dir(), "to": config.TOKEN_EMULATOR_SETUP_ROOT},
                {"from": game_info.get_save_dir(), "to": config.TOKEN_GAME_SAVE_DIR}
            ],
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    if not paths.is_path_valid(game_launcher_save_dir):
        return True
    success = fileops.remove_object(
        obj = game_launcher_save_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False
    return fileops.make_directory(
        src = game_launcher_save_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Cache the game, import its save, point the emulator's save dir and config at it, launch, then revert them and export the save
def launch_local_game(
    game_info,
    locker_type = None,
    capture_type = None,
    fullscreen = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check game info
    if not game_info or not game_info.is_valid() or not game_info.is_playable():
        return False

    # Install local game
    success = install_local_game(
        game_info = game_info,
        locker_type = locker_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Get launcher
    game_launcher = emulators.get_emulator_by_platform(game_info.get_platform())
    if not game_launcher:
        gui.display_error_popup(
            title_text = "Launcher not found",
            message_text = "Launcher for game '%s' in platform '%s' could not be found" % (game_info.get_name(), game_info.get_platform()))
        return False

    # Get game launcher info
    game_launcher_config_file = game_launcher.get_config_file()
    game_launcher_save_dir = game_launcher.get_save_dir(game_info.get_platform())
    game_launcher_setup_dir = game_launcher.get_setup_dir()

    # Import save
    success = import_local_game_save(
        game_info = game_info,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Setup launcher save directory
    if paths.is_path_valid(game_launcher_save_dir):
        success = fileops.create_symlink(
            src = game_info.get_save_dir(),
            dest = game_launcher_save_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

    # Setup launcher config file
    if paths.is_path_file(game_launcher_config_file):
        fileedits.replace_strings_in_file(
            src = game_launcher_config_file,
            replacements = [
                {"from": config.TOKEN_EMULATOR_SETUP_ROOT, "to": game_launcher_setup_dir},
                {"from": config.TOKEN_GAME_SAVE_DIR, "to": game_info.get_save_dir()}
            ],
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Launch game, then revert the launcher even when the launch failed
    launched = game_launcher.launch(
        game_info = game_info,
        capture_type = capture_type,
        fullscreen = fullscreen,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    reverted = _revert_launcher_setup(
        game_info = game_info,
        game_launcher = game_launcher,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not launched or not reverted:
        return False

    # Export save
    success = export_local_game_save(
        game_info = game_info,
        locker_type = locker_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

###########################################################

# Launch through the store client for store platforms, otherwise through the platform's emulator
def launch_game(
    game_info,
    locker_type = None,
    capture_type = None,
    fullscreen = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if stores.is_store_platform(game_info.get_platform()):
        return launch_store_game(
            game_info = game_info,
            locker_type = locker_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return launch_local_game(
        game_info = game_info,
        locker_type = locker_type,
        capture_type = capture_type,
        fullscreen = fullscreen,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

###########################################################
