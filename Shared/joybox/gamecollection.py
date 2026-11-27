# Finding the games stored under a category, and iterating the games and
# categories a command selected.

# Imports
import os

# Local imports
from joybox import config
from joybox import environment
from joybox import gameinfo
from joybox import gamenaming
from joybox import logger
from joybox import paths
from joybox import platforms

# Find best suited game file
def find_best_game_file(game_files):

    # Collect game file entries
    game_file_entries = []
    if isinstance(game_files, list):
        for file in game_files:
            game_file_entry = {}
            game_file_entry["file"] = os.path.abspath(file)
            game_file_entry["weight"] = config.GAMETYPE_WEIGHT_ELSE
            for key in config.gametype_weights.keys():
                if file.endswith(key):
                    game_file_entry["weight"] = config.gametype_weights[key]
                    break
            game_file_entries.append(game_file_entry)

    # Use this to get the best file
    game_file = ""
    for game_file_entry in sorted(game_file_entries, key=lambda d: d["weight"]):
        game_file = game_file_entry["file"]
        break
    return game_file

# Find all game names
def find_all_game_names(base_dir, game_supercategory, game_category, game_subcategory):

    # Get base path
    base_path = paths.join_paths(base_dir, game_supercategory, game_category, game_subcategory)

    # Get platform
    game_platform = gamenaming.derive_game_platform_from_categories(game_subcategory)

    # Collect game names
    game_names = []
    if platforms.is_letter_platform(game_platform):
        for game_letter in sorted(paths.get_directory_contents(base_path)):
            for game_name in sorted(paths.get_directory_contents(paths.join_paths(base_path, game_letter))):
                game_names.append(game_name)
    else:
        for game_name in sorted(paths.get_directory_contents(base_path)):
            game_names.append(game_name)
    return game_names

# Find json game names, narrowed to the games with files in a locker when one is given
def find_json_game_names(game_supercategory, game_category, game_subcategory, locker_type = None):
    base_dir = environment.get_game_json_metadata_root_dir()
    game_names = find_all_game_names(base_dir, game_supercategory, game_category, game_subcategory)
    if locker_type:
        locker_game_names = set(find_locker_game_names(game_supercategory, game_category, game_subcategory, locker_type))
        game_names = [game_name for game_name in game_names if game_name in locker_game_names]
    return game_names

# Find locker game names
def find_locker_game_names(game_supercategory, game_category, game_subcategory, locker_type = None, locker_base_dir = None):
    if locker_base_dir:
        base_dir = paths.join_paths(locker_base_dir, config.LockerFolderType.GAMING)
    else:
        base_dir = environment.get_locker_gaming_root_dir(locker_type)
    return find_all_game_names(base_dir, game_supercategory, game_category, game_subcategory)

# Iterate every rom category, as (supercategory, category, subcategory)
def iterate_rom_categories():
    for game_category in config.Category.members():
        for game_subcategory in config.subcategory_map[game_category]:
            yield config.Supercategory.ROMS, game_category, game_subcategory

# Iterate the info of every rom game with json metadata
def iterate_rom_game_infos(verbose = False, exit_on_failure = False):
    for game_supercategory, game_category, game_subcategory in iterate_rom_categories():
        for game_name in find_json_game_names(game_supercategory, game_category, game_subcategory):
            yield gameinfo.GameInfo(
                game_supercategory = game_supercategory,
                game_category = game_category,
                game_subcategory = game_subcategory,
                game_name = game_name,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

# Iterate selected game categories
def iterate_selected_game_categories(
    parser,
    generation_mode = None,
    game_supercategories = None,
    game_subcategory_map = None):

    # Determine generation mode
    args, _ = parser.parse_known_args()
    if generation_mode is None:
        generation_mode = getattr(args, "generation_mode", config.GenerationModeType.STANDARD)

    # Custom mode - yield single category tuple from explicit args
    if generation_mode == config.GenerationModeType.CUSTOM:
        if not args.game_category:
            raise ValueError("Game category is required for custom mode")
        if not args.game_subcategory:
            raise ValueError("Game subcategory is required for custom mode")
        yield (args.game_supercategory, args.game_category, args.game_subcategory)
        return

    # Standard mode - iterate filesystem
    if game_supercategories is None:
        game_supercategories = parser.get_selected_supercategories()
    if game_subcategory_map is None:
        game_subcategory_map = parser.get_selected_subcategories()
    for game_supercategory in sorted(game_supercategories):
        for game_category, game_subcategories in sorted(game_subcategory_map.items()):
            for game_subcategory in sorted(game_subcategories):
                yield (game_supercategory, game_category, game_subcategory)

# Iterate selected game infos
def iterate_selected_game_infos(
    parser,
    generation_mode = None,
    locker_type = None,
    locker_base_dir = None,
    game_supercategories = None,
    game_subcategory_map = None,
    game_name_filter = None,
    verbose = False,
    exit_on_failure = False):

    # Determine generation mode
    args, _ = parser.parse_known_args()
    if generation_mode is None:
        generation_mode = getattr(args, "generation_mode", config.GenerationModeType.STANDARD)

    # Custom mode - yield single GameInfo from explicit args
    if generation_mode == config.GenerationModeType.CUSTOM:
        if not args.game_category:
            raise ValueError("Game category is required for custom mode")
        if not args.game_subcategory:
            raise ValueError("Game subcategory is required for custom mode")
        if not args.game_name:
            raise ValueError("Game name is required for custom mode")
        yield gameinfo.GameInfo(
            game_supercategory = args.game_supercategory,
            game_category = args.game_category,
            game_subcategory = args.game_subcategory,
            game_name = args.game_name,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        return

    # Standard mode - iterate filesystem
    if game_name_filter is None:
        game_name_filter = getattr(args, "game_name", None)
    for game_supercategory, game_category, game_subcategory in iterate_selected_game_categories(
        parser = parser,
        generation_mode = generation_mode,
        game_supercategories = game_supercategories,
        game_subcategory_map = game_subcategory_map):
        if locker_type is not None or locker_base_dir is not None:
            game_names = find_locker_game_names(
                game_supercategory,
                game_category,
                game_subcategory,
                locker_type,
                locker_base_dir)
        else:
            game_names = find_json_game_names(
                game_supercategory,
                game_category,
                game_subcategory)
        if game_name_filter:
            game_names = [g for g in game_names if g == game_name_filter]
        for game_name in game_names:
            try:
                yield gameinfo.GameInfo(
                    game_supercategory = game_supercategory,
                    game_category = game_category,
                    game_subcategory = game_subcategory,
                    game_name = game_name,
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)
            except (OSError, ValueError) as e:
                logger.log_warning("Skipping '%s': %s" % (game_name, str(e)))
