# Imports
import random

# Local imports
from joybox import config
from joybox import datautils
from joybox import logger
from joybox import environment
from joybox import gamenaming
from joybox import metadataentry
from joybox import paths
from joybox import reports
from joybox import serialization

# Pegasus field prefixes before the description, with the MetadataEntry accessor suffix for each
PEGASUS_FIELDS_BEFORE_DESCRIPTION = [
    ("game:", "game"),
    ("file:", "file"),
    ("developer:", "developer"),
    ("publisher:", "publisher"),
    ("genre:", "genre"),
]

# Pegasus field prefixes after the description, with the MetadataEntry accessor suffix for each
PEGASUS_FIELDS_AFTER_DESCRIPTION = [
    ("release:", "release"),
    ("players:", "players"),
    ("assets.boxfront:", "boxfront"),
    ("assets.boxback:", "boxback"),
    ("assets.background:", "background"),
    ("assets.screenshot:", "screenshot"),
    ("assets.video:", "video"),
    ("x-url:", "url"),
    ("x-co-op:", "coop"),
    ("x-playable:", "playable"),
]

# Collection name from the first "collection:" line of Pegasus text; empty when there is none
def read_pegasus_collection_name(data):
    for line in data.split("\n"):
        if line.startswith("collection:"):
            return line.replace("collection:", "").strip()
    return ""

# Apply one Pegasus line to the entry and return whether a description block continues after it
def apply_pegasus_line(game_entry, line, in_description_section):
    for prefix, field in PEGASUS_FIELDS_BEFORE_DESCRIPTION:
        if line.startswith(prefix):
            getattr(game_entry, "set_" + field)(line.replace(prefix, "").strip())
            return False

    # Tag (no field in the metadata model; ends a description)
    if line.startswith("tag:"):
        return False

    # Description
    if line.startswith("description:"):
        game_entry.set_description([])
        return True
    if line.startswith("  ") and in_description_section:
        description_lines = game_entry.get_description()
        description_lines.append(line.strip())
        game_entry.set_description(description_lines)
        return True
    for prefix, field in PEGASUS_FIELDS_AFTER_DESCRIPTION:
        if line.startswith(prefix):
            getattr(game_entry, "set_" + field)(line.replace(prefix, "").strip())
            return False
    return in_description_section

# Metadata entry for the platform built from one blank-line separated Pegasus block
def parse_pegasus_entry(token, game_platform):
    game_entry = metadataentry.MetadataEntry()
    game_entry.set_platform(game_platform)
    in_description_section = False
    for line in token.split("\n"):
        in_description_section = apply_pegasus_line(game_entry, line, in_description_section)
    return game_entry

# Pegasus text pieces for one entry's set fields, ending with the entry divider
def format_pegasus_entry(game_entry):
    contents = []
    for prefix, field in PEGASUS_FIELDS_BEFORE_DESCRIPTION:
        value = getattr(game_entry, "get_" + field)()
        if value:
            contents.append(prefix + " " + value + "\n")

    # Description
    if game_entry.get_description():
        contents.append("description:\n")
        for desc_line in game_entry.get_description():
            contents.append("  " + desc_line + "\n")
    for prefix, field in PEGASUS_FIELDS_AFTER_DESCRIPTION:
        value = getattr(game_entry, "get_" + field)()
        if value:
            contents.append(prefix + " " + value + "\n")

    # Divider
    contents.append("\n\n")
    return contents

# Metadata database class
class Metadata:

    # Constructor
    def __init__(self):
        self.game_database = {}

    # Add game entry
    def add_game(self, game_entry):

        # Check minimum keys
        if not game_entry.has_minimum_keys():
            return

        # Get game info
        game_platform = game_entry.get_platform()
        game_name = game_entry.get_game()

        # Inject categories
        game_supercategory, game_category, game_subcategory = gamenaming.derive_game_categories_from_platform(game_platform)
        game_entry.set_supercategory(game_supercategory)
        game_entry.set_category(game_category)
        game_entry.set_subcategory(game_subcategory)

        # Add entry
        self.set_game(game_platform, game_name, game_entry)

    # Check if game entry exists
    def has_game(self, game_platform, game_name):
        if game_platform not in self.game_database:
            return False
        return game_name in self.game_database[game_platform]

    # Get game entry
    def get_game(self, game_platform, game_name):
        if game_platform in self.game_database:
            if game_name in self.game_database[game_platform]:
                return self.game_database[game_platform][game_name]
        return None

    # Set game entry
    def set_game(self, game_platform, game_name, game_entry):
        if game_platform not in self.game_database.keys():
            self.game_database[game_platform] = {}
        if game_name in self.game_database[game_platform]:
            self.game_database[game_platform][game_name].merge(game_entry)
        else:
            self.game_database[game_platform][game_name] = game_entry

    # Platforms present in the game database, in alphabetical order
    def get_sorted_platforms(self):
        potential_platforms = []
        for platform in self.game_database.keys():
            potential_platforms.append(platform)
        return sorted(potential_platforms)

    # Get sorted names within a platform
    def get_sorted_names(self, game_platform):
        if game_platform not in self.game_database:
            return []
        potential_names = []
        for name in self.game_database[game_platform].keys():
            potential_names.append(name)
        return sorted(potential_names)

    # Game names across every platform, platform by platform, each alphabetized
    def get_all_sorted_names(self):
        names = []
        for game_platform in self.get_sorted_platforms():
            names += self.get_sorted_names(game_platform)
        return names

    # Entries for one platform, ordered by game name
    def get_sorted_entries(self, game_platform):
        entries = []
        for game_name in self.get_sorted_names(game_platform):
            entries.append(self.get_game(game_platform, game_name))
        return entries

    # Entries across every platform, ordered by platform then game name
    def get_all_sorted_entries(self):
        entries = []
        for game_platform in self.get_sorted_platforms():
            entries += self.get_sorted_entries(game_platform)
        return entries

    # One entry picked at random from a non-empty platform; None when the database is empty
    def get_random_entry(self):
        game_platforms = [platform for platform in self.get_sorted_platforms() if self.get_sorted_names(platform)]
        if not game_platforms:
            return None
        game_platform = random.choice(game_platforms)
        game_name = random.choice(self.get_sorted_names(game_platform))
        game_entry = self.get_game(game_platform, game_name)
        return game_entry

    # Check if entry is missing data
    def is_entry_missing_data(self, game_platform, game_name, keys_to_check):
        return self.get_game(game_platform, game_name).is_missing_data(keys_to_check)

    # Check if missing data
    def is_missing_data(self, keys_to_check):
        for game_platform in self.get_sorted_platforms():
            for game_name in self.get_sorted_names(game_platform):
                if self.is_entry_missing_data(game_platform, game_name, keys_to_check):
                    return True
        return False

    # Merge with other metadata
    def merge_contents(self, other, merge_type = None):
        if not merge_type:
            merge_type = config.MergeType.REPLACE
        self.game_database = datautils.merge_dictionaries(
            dict1 = self.game_database,
            dict2 = other.game_database,
            merge_type = merge_type)

    # Sync assets in each entry
    def sync_assets(self):
        for entry in self.get_all_sorted_entries():
            entry.sync_assets()

    # Check each entry's file exists under the JSON metadata root; False at the first missing one
    def verify_files(
        self,
        verbose = False,
        exit_on_failure = False):
        for game_platform in self.get_sorted_platforms():
            for game_name in self.get_sorted_names(game_platform):
                if verbose:
                    logger.log_info("Checking '%s - %s' ..." % (game_platform, game_name))

                # Get game entry
                game_entry = self.get_game(game_platform, game_name)

                # Check file paths
                file_path_relative = game_entry.get_file()
                file_path_real = paths.join_paths(environment.get_game_json_metadata_root_dir(), file_path_relative)
                if not paths.does_path_exist(file_path_real):
                    logger.log_error("File not found:\n%s" % file_path_relative)
                    logger.log_error("Verification of '%s - %s' failed" % (game_platform, game_name), quit_program = exit_on_failure)
                    return False
        return True

    # Parse a Pegasus metadata.txt into entries for its collection platform, keeping those with the minimum keys
    def import_from_pegasus_file(
        self,
        pegasus_file,
        verbose = False,
        exit_on_failure = False):
        if not paths.does_path_exist(pegasus_file):
            return
        data = serialization.read_text_file(pegasus_file, verbose = verbose, exit_on_failure = exit_on_failure)
        if data is None:
            return

        # Read header
        game_platform = config.Platform.from_string(read_pegasus_collection_name(data))
        if not game_platform:
            logger.log_error("No known collection platform in %s" % pegasus_file)
            return

        # Read game entries
        for token in data.split("\n\n"):
            game_entry = parse_pegasus_entry(token, game_platform)
            if game_entry.has_minimum_keys():
                self.add_game(game_entry)

    # Import a metadata file by its format; only Pegasus is handled
    def import_from_metadata_file(
        self,
        metadata_file,
        metadata_format = config.MetadataFormatType.PEGASUS,
        verbose = False,
        exit_on_failure = False):
        if metadata_format == config.MetadataFormatType.PEGASUS:
            self.import_from_pegasus_file(
                pegasus_file = metadata_file,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

    # Write every platform's entries as Pegasus collections with a launch line, optionally after the file's existing text
    def export_to_pegasus_file(
        self,
        pegasus_file,
        append_existing = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        contents = []
        if append_existing and paths.does_path_exist(pegasus_file):
            contents.append(serialization.read_text_file(
                src = pegasus_file,
                verbose = verbose,
                exit_on_failure = exit_on_failure) or "")
        for game_platform in self.get_sorted_platforms():
            _, game_category, game_subcategory = gamenaming.derive_game_categories_from_platform(game_platform)

            # Get launch command
            launch_cmd = [
                "{env.JOYBOX_LAUNCH_JSON}",
                "-c", "\"" + game_category + "\"",
                "-s", "\"" + game_subcategory + "\"",
                "-n", "{file.basename}"
            ]

            # Write header
            contents.append("collection: %s\n" % game_platform.val())
            contents.append("launch: %s\n" % " ".join(launch_cmd))
            contents.append("\n\n")

            # Write each entry
            for game_entry in self.get_sorted_entries(game_platform):
                contents += format_pegasus_entry(game_entry)

        # Write file
        return serialization.write_text_file(
            src = pegasus_file,
            contents = "".join(contents),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Export to a metadata file in the given format; only Pegasus is handled
    def export_to_metadata_file(
        self,
        metadata_file,
        metadata_format = config.MetadataFormatType.PEGASUS,
        append_existing = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        if metadata_format == config.MetadataFormatType.PEGASUS:
            self.export_to_pegasus_file(
                pegasus_file = metadata_file,
                append_existing = append_existing,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

###########################################################
# Missing asset and metadata reports
###########################################################

# (platform, entry) for every game entry of each Pegasus metadata file under the directory
def _iterate_metadata_dir_entries(metadata_dir):
    for filename in paths.build_file_list(metadata_dir):
        if not environment.is_game_metadata_file(filename):
            continue
        metadata_obj = Metadata()
        metadata_obj.import_from_metadata_file(filename)
        for game_platform in metadata_obj.get_sorted_platforms():
            for game_entry in metadata_obj.get_sorted_entries(game_platform):
                yield game_platform, game_entry

# (asset files present, missing asset files by asset type) over every asset type of every entry
def _find_entry_asset_files(metadata_dir):
    found_assets = set()
    missing_assets = {}
    for game_platform, game_entry in _iterate_metadata_dir_entries(metadata_dir):
        for asset_type in config.AssetType.members():

            # Get asset file
            game_name = game_entry.get_game()
            _, game_category, game_subcategory = gamenaming.derive_game_categories_from_platform(game_platform)
            asset_file = environment.get_locker_gaming_asset_file(game_category, game_subcategory, game_name, asset_type)

            # Check if asset exists
            if paths.does_path_exist(asset_file):
                found_assets.add(asset_file)
            else:
                missing_assets.setdefault(asset_type, set()).add(asset_file)
    return found_assets, missing_assets

# Report the Pegasus entries missing each asset type and the asset files no entry uses, writing
# each list to a file
def report_missing_game_assets(assets_dir, metadata_dir, verbose = False, pretend_run = False):
    all_assets = set(paths.build_file_list(assets_dir))
    found_assets, missing_assets = _find_entry_asset_files(metadata_dir)

    # Report and write missing assets
    for asset_type in config.AssetType.members():
        reports.write_list_report(
            items = sorted(missing_assets.get(asset_type, set())),
            title = "\nMissing '%s':" % asset_type.val(),
            max_display = 10 if verbose else 0,
            report_file = "Missing_%s.txt" % asset_type.val(),
            verbose = verbose,
            pretend_run = pretend_run)

    # Report and write extra assets
    extra_assets = all_assets - found_assets
    for asset_files in missing_assets.values():
        extra_assets = extra_assets - asset_files
    reports.write_list_report(
        items = sorted(extra_assets),
        title = "\nExtra assets:",
        max_display = 10 if verbose else 0,
        report_file = "Extras.txt",
        verbose = verbose,
        pretend_run = pretend_run)

# The metadata keys a key set selects: the minimum, the downloadable or all of them
def get_metadata_keys_to_check(key_type):
    if key_type == config.MetadataKeyType.MINIMUM:
        return config.metadata_keys_minimum
    if key_type == config.MetadataKeyType.DOWNLOADABLE:
        return config.metadata_keys_downloadable
    return config.metadata_keys_all

# Log a summary of the Pegasus entries missing any of the keys, then write per key the entries
# missing it
def report_missing_game_metadata(metadata_dir, keys_to_check, verbose = False, pretend_run = False):
    missing_by_key = {key: [] for key in keys_to_check}
    total_entries = 0
    entries_with_missing = set()
    for game_platform, game_entry in _iterate_metadata_dir_entries(metadata_dir):
        total_entries += 1
        entry_id = "%s - %s" % (game_platform, game_entry.get_game())
        for key in keys_to_check:
            if not game_entry.is_key_set(key) or game_entry.get_value(key) == "":
                missing_by_key[key].append(entry_id)
                entries_with_missing.add(entry_id)
    logger.log_header("Scan complete: %d total entries, %d with missing metadata" % (total_entries, len(entries_with_missing)))

    # Write results per key
    for key in keys_to_check:
        missing_items = sorted(missing_by_key[key])
        if len(missing_items) > 0:
            reports.write_list_report(
                items = missing_items,
                title = "\nMissing '%s':" % key,
                max_display = 10 if verbose else 0,
                report_file = "Missing_%s.txt" % key,
                verbose = verbose,
                pretend_run = pretend_run)

###########################################################
# Sorting metadata files
###########################################################

# The game metadata files anywhere under metadata_dir
def find_game_metadata_files(metadata_dir):
    metadata_files = []
    for filename in paths.build_file_list(metadata_dir):
        if environment.is_game_metadata_file(filename):
            metadata_files.append(filename)
    return metadata_files

# Rewrite each metadata file in sorted order by importing it and exporting it back, logging
# each and then the count; a pretend run only logs them
def sort_game_metadata_files(metadata_files, verbose = False, pretend_run = False):
    files_sorted = 0
    for metadata_file in sorted(metadata_files):
        logger.log_info("Sorting: %s" % metadata_file)
        if not pretend_run:

            # Import metadata
            metadata_obj = Metadata()
            metadata_obj.import_from_metadata_file(metadata_file)

            # Export back
            metadata_obj.export_to_metadata_file(
                metadata_file = metadata_file,
                append_existing = False,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = False)
        files_sorted += 1

    # Report results
    logger.log_header("Sort complete: %d files sorted" % files_sorted)
