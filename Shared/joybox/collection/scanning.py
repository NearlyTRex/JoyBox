# Collection scans: building every generated game file in pipeline order, and
# verifying that the generated files point at real game files.

# Imports
import os

# Local imports
from joybox import config
from joybox import environment
from joybox import gamecollection
from joybox import gameinfo
from joybox import hashing
from joybox import logger
from joybox import manifest
from joybox import metadata
from joybox import paths
from .asset import download_all_metadata_assets
from .jsondata import build_all_game_json_files
from .metadata import build_all_game_metadata_entries
from .metadata import publish_all_game_metadata_entries
from .purchase import build_all_game_store_purchases

############################################################
# Building
############################################################

# Quit on any comma-separated category or subcategory filter value that names none, since
# an unknown value would otherwise widen the run to everything; log the filters given
def check_scan_filters(categories = None, subcategories = None):
    for filter_values, filter_type in [(categories, config.Category), (subcategories, config.Subcategory)]:
        if filter_values:
            unknown_values = [value.strip() for value in filter_values.split(",") if value.strip() and not filter_type.from_string(value.strip())]
            if unknown_values:
                logger.log_error("Unknown %s values: %s" % (filter_type.__name__, ", ".join(unknown_values)), quit_program = True)
    if categories:
        logger.log_info(f"Filtering to categories: {categories}")
    if subcategories:
        logger.log_info(f"Filtering to subcategories: {subcategories}")

# Log a scan step's start and run it with the keyword arguments given; quits with its
# failure message when it fails
def _run_scan_step(start_message, failure_message, step, **kwargs):
    logger.log_info(start_message)
    if not step(**kwargs):
        logger.log_error(failure_message, quit_program = True)

# Build store purchases unless skipped, then json files, metadata files, metadata assets
# when asked, and publish the metadata; with purchases skipped, metadata and assets cover
# only the locker's games. Quits on the first step that fails.
def scan_game_files(
    categories = None,
    subcategories = None,
    locker_type = None,
    skip_purchases = False,
    load_manifest = False,
    create_playlists = False,
    download_assets = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    flags = {"verbose": verbose, "pretend_run": pretend_run, "exit_on_failure": exit_on_failure}
    filters = {"categories": categories, "subcategories": subcategories}
    scanned_locker_type = (locker_type or config.LockerType.LOCAL) if skip_purchases else None
    if load_manifest:
        logger.log_info("Loading manifest ...")
        manifest.get_manifest_instance().load(verbose = verbose, exit_on_failure = exit_on_failure)
    if not skip_purchases:
        _run_scan_step("Building store purchases ...", "Building store purchases failed",
            build_all_game_store_purchases, **filters, **flags)
    _run_scan_step("Building json files ...", "Building json files failed",
        build_all_game_json_files, locker_type = locker_type, **filters, create_disc_playlists = create_playlists, **flags)
    _run_scan_step("Building metadata files ...", "Building metadata files failed",
        build_all_game_metadata_entries, **filters, locker_type = scanned_locker_type, **flags)
    if download_assets:
        _run_scan_step("Downloading metadata assets ...", "Downloading metadata assets failed",
            download_all_metadata_assets, **filters, locker_type = scanned_locker_type, skip_existing = True, **flags)
    _run_scan_step("Publishing metadata files ...", "Publishing metadata files failed",
        publish_all_game_metadata_entries, **filters, **flags)

############################################################
# Verifying
############################################################

# Every supercategory, category and subcategory combination, in config order
def _iterate_game_categories():
    for game_supercategory in config.Supercategory.members():
        for game_category in config.Category.members():
            for game_subcategory in config.subcategory_map[game_category]:
                yield game_supercategory, game_category, game_subcategory

# Quit on a json file whose game has no directory in the locker
def _check_json_files_have_games():
    for json_file in paths.build_file_list_by_extensions(environment.get_game_json_metadata_root_dir(), extensions = [".json"]):
        logger.log_info("Checking if game matching '%s' exists ..." % json_file)
        game_supercategory, game_category, game_subcategory = gameinfo.derive_game_categories_from_file(json_file)
        game_name = paths.get_filename_basename(json_file)
        game_base_dir = environment.get_locker_gaming_files_dir(game_supercategory, game_category, game_subcategory, game_name)
        if not os.path.exists(game_base_dir):
            logger.log_error("Extraneous json file '%s' found" % json_file, quit_program = True)

# Verify the files every category's metadata file names, quitting on the first missing one
def _verify_metadata_files(verbose):
    for game_category in config.Category.members():
        for game_subcategory in config.subcategory_map[game_category]:
            metadata_file = environment.get_game_metadata_file(game_category, game_subcategory)
            if paths.is_path_file(metadata_file):
                metadata_obj = metadata.Metadata()
                metadata_obj.import_from_metadata_file(metadata_file)
                metadata_obj.verify_files(verbose = verbose, exit_on_failure = True)

# Quit on a file a game's json names, its files plus its transform or else launch file,
# that is missing from the game's locker directory; a game without a json file is skipped
def _check_json_game_files(game_supercategory, game_category, game_subcategory, game_name, verbose, exit_on_failure):
    json_file = environment.get_game_json_metadata_file(game_supercategory, game_category, game_subcategory, game_name)
    if not paths.is_path_file(json_file):
        return
    game_info = gameinfo.GameInfo(
        json_file = json_file,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    files_to_check = list(game_info.get_files())
    json_launch_file = game_info.get_launch_file()
    json_transform_file = game_info.get_transform_file()
    if json_transform_file:
        files_to_check.append(json_transform_file)
    elif json_launch_file:
        files_to_check.append(json_launch_file)
    for file_to_check in files_to_check:
        stored_file = paths.join_paths(
            environment.get_locker_gaming_files_dir(game_supercategory, game_category, game_subcategory, game_name),
            file_to_check)
        if not os.path.exists(stored_file):
            logger.log_error("File '%s' referenced in json file not found" % file_to_check, quit_program = True)

# Quit on a file a category's hash file names that is missing from the locker; a category without one is skipped
def _check_hash_file_references(game_supercategory, game_category, game_subcategory):
    hash_file_path = environment.get_game_hashes_metadata_file(game_supercategory, game_category, game_subcategory)
    if not os.path.exists(hash_file_path):
        return
    logger.log_info("Checking hash file '%s' ..." % hash_file_path)
    hash_file_data = hashing.read_hash_file_json(hash_file_path)
    for hash_reference_file in hash_file_data:
        stored_file = paths.join_paths(environment.get_locker_gaming_root_dir(), hash_reference_file)
        if not os.path.exists(stored_file):
            logger.log_error("File '%s' referenced in hash file not found" % stored_file, quit_program = True)

# Check every json file has a game, the files each metadata, json and hash file names
# exist, in that order; quits on the first mismatch
def verify_game_files(verbose = False, exit_on_failure = False):
    _check_json_files_have_games()
    _verify_metadata_files(verbose)
    for game_supercategory, game_category, game_subcategory in _iterate_game_categories():
        for game_name in gamecollection.find_json_game_names(game_supercategory, game_category, game_subcategory):
            _check_json_game_files(game_supercategory, game_category, game_subcategory, game_name, verbose, exit_on_failure)
    for game_supercategory, game_category, game_subcategory in _iterate_game_categories():
        _check_hash_file_references(game_supercategory, game_category, game_subcategory)
