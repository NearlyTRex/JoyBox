# Imports
import random

# Local imports
from joybox import emulators
from joybox import config
from joybox import fileops
from joybox import fileedits
from joybox import stores
from joybox import gui
from joybox import paths
from joybox import environment
from joybox import platforms
from joybox import metadata
from joybox import gameinfo
from joybox import gamenaming
from joybox.collection import installing
from .installing import install_store_game
from .installing import install_local_game
from .saves import export_store_game_save
from .saves import import_local_game_save
from .saves import export_local_game_save

###########################################################

# Launch the game through its store client by its install identifier; False when the store does not handle launching
def _launch_through_store(
    game_info,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

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
    return store_obj.launch(
        identifier = store_identifier,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

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

    # Launch game
    success = _launch_through_store(
        game_info = game_info,
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

# The platform's emulator for the game, or None after a popup saying none was found
def _find_game_launcher(game_info):
    game_launcher = emulators.get_emulator_by_platform(game_info.get_platform())
    if not game_launcher:
        gui.display_error_popup(
            title_text = "Launcher not found",
            message_text = "Launcher for game '%s' in platform '%s' could not be found" % (game_info.get_name(), game_info.get_platform()))
    return game_launcher

# Symlink the launcher's save dir to the game's and fill the tokens in its config file
def _apply_launcher_setup(
    game_info,
    game_launcher,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get game launcher info
    game_launcher_config_file = game_launcher.get_config_file()
    game_launcher_save_dir = game_launcher.get_save_dir(game_info.get_platform())
    game_launcher_setup_dir = game_launcher.get_setup_dir()

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
    return True

# Launch the game in the emulator, revert the launcher even when the launch failed, then export the save
def _run_launcher(
    game_info,
    game_launcher,
    locker_type = None,
    capture_type = None,
    fullscreen = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

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

# Point the emulator's save dir and config at the game, then run it and export the save
def _run_with_launcher_setup(
    game_info,
    game_launcher,
    locker_type = None,
    capture_type = None,
    fullscreen = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Setup launcher
    success = _apply_launcher_setup(
        game_info = game_info,
        game_launcher = game_launcher,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Launch game
    return _run_launcher(
        game_info = game_info,
        game_launcher = game_launcher,
        locker_type = locker_type,
        capture_type = capture_type,
        fullscreen = fullscreen,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Find the platform's emulator, import the game's save, then run the game there and export the save
def _play_with_launcher(
    game_info,
    locker_type = None,
    capture_type = None,
    fullscreen = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get launcher
    game_launcher = _find_game_launcher(game_info)
    if not game_launcher:
        return False

    # Import save
    success = import_local_game_save(
        game_info = game_info,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Setup launcher and launch game
    return _run_with_launcher_setup(
        game_info = game_info,
        game_launcher = game_launcher,
        locker_type = locker_type,
        capture_type = capture_type,
        fullscreen = fullscreen,
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

    # Play game
    return _play_with_launcher(
        game_info = game_info,
        locker_type = locker_type,
        capture_type = capture_type,
        fullscreen = fullscreen,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

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

# A random subcategory of the category whose platform has a launcher
def _choose_random_launchable_subcategory(game_category):
    potential_subcategories = []
    for potential_subcategory in config.subcategory_map[game_category]:
        potential_platform = gamenaming.derive_game_platform_from_categories(potential_subcategory)
        if not platforms.has_no_launcher(potential_platform):
            potential_subcategories.append(potential_subcategory)
    return random.choice(potential_subcategories)

# The JSON file of a random game, picking the category and subcategory at random when not given;
# None when the platform's metadata has no entry
def choose_random_game_json_file(game_category = None, game_subcategory = None):
    if not game_category:
        game_category = random.choice(config.Category.members())
    if not game_subcategory:
        game_subcategory = _choose_random_launchable_subcategory(game_category)

    # Select a random entry from this category/subcategory pair's metadata
    metadata_file = environment.get_game_metadata_file(game_category, game_subcategory)
    metadata_obj = metadata.Metadata()
    metadata_obj.import_from_metadata_file(metadata_file)
    random_game_entry = metadata_obj.get_random_entry()
    if not random_game_entry:
        return None
    return environment.get_game_json_metadata_file(
        game_supercategory = config.Supercategory.ROMS,
        game_category = game_category,
        game_subcategory = game_subcategory,
        game_name = random_game_entry.get_game())

# The game JSON file to launch: the given one, else the one category, subcategory and name point
# to, else a random one when asked; None when none applies
def select_game_json_file(json_file = None, game_category = None, game_subcategory = None, game_name = None, fill_with_random = False):
    if json_file:
        return json_file
    if game_category and game_subcategory and game_name:
        return installing.get_named_game_json_file(game_category, game_subcategory, game_name)
    if fill_with_random:
        return choose_random_game_json_file(game_category, game_subcategory)
    return None

# Launch the playable game of the selected JSON file, installing it and restoring its save first;
# an error popup quits when there is no such file or game, or the launch fails
def launch_game_from_json(
    json_file = None,
    game_category = None,
    game_subcategory = None,
    game_name = None,
    fill_with_random = False,
    locker_type = None,
    capture_type = None,
    fullscreen = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    json_file = select_game_json_file(json_file, game_category, game_subcategory, game_name, fill_with_random)
    installing.check_game_json_file(json_file)
    game_info = gameinfo.GameInfo(
        json_file = json_file,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if not game_info.is_playable():
        gui.display_error_popup(
            title_text = "Json file not launchable",
            message_text = "Json file '%s' is not launchable" % paths.get_filename_file(json_file))
    success = launch_game(
        game_info = game_info,
        locker_type = locker_type,
        capture_type = capture_type,
        fullscreen = fullscreen,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        gui.display_error_popup(
            title_text = "Json file failed to launch",
            message_text = "Json file '%s' failed to launch" % paths.get_filename_file(json_file))
