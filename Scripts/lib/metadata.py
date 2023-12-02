# Imports
import os
import os.path
import sys
import re
import urllib.parse
import datetime
import time
import pathlib
import textwrap
import random

# Custom imports
lib_folder = os.path.realpath(os.path.dirname(__file__))
sys.path.append(lib_folder)
import config
import system
import webpage
import environment
import network

# General metadata class
class Metadata:

    # Constructor
    def __init__(self):
        self.game_database = {}

    # Add game entry
    def add_game(self, game_entry):

        # Check minimum keys
        for key in GetMinimumMetadataKeys():
            if not key in game_entry:
                return

        # Get game info
        game_platform = game_entry[config.metadata_key_platform]
        game_name = game_entry[config.metadata_key_game]

        # Add game
        if not game_platform in self.game_database.keys():
            self.game_database[game_platform] = {}
        self.game_database[game_platform][game_name] = game_entry

    # Get game entry
    def get_game(self, game_platform, game_name):
        return self.game_database[game_platform][game_name]

    # Set game entry
    def set_game(self, game_platform, game_name, game_entry):
        self.game_database[game_platform][game_name] = game_entry

    # Get sorted platforms
    def get_sorted_platforms(self, filter_options = {}):
        platforms = []
        for platform in self.game_database.keys():
            only_launchable = GetFilterOption(filter_options, config.filter_launchable_only)
            no_launcher_set = (platform in config.no_launcher_platforms)
            if only_launchable and no_launcher_set:
                continue
            platforms.append(platform)
        return sorted(platforms)

    # Get sorted names within a platform
    def get_sorted_names(self, game_platform, filter_options = {}):
        if not game_platform in self.game_database:
            return []
        return sorted(self.game_database[game_platform].keys())

    # Get all sorted names
    def get_all_sorted_names(self, filter_options = {}):
        names = []
        for game_platform in self.get_sorted_platforms(filter_options):
            names += self.get_sorted_names(game_platform, filter_options)
        return names

    # Get sorted entries
    def get_sorted_entries(self, game_platform, filter_options = {}):
        entries = []
        for game_name in self.get_sorted_names(game_platform, filter_options):
            entries.append(self.get_game(game_platform, game_name))
        return entries

    # Get all sorted entries
    def get_all_sorted_entries(self, filter_options = {}):
        entries = []
        for game_platform in self.get_sorted_platforms(filter_options):
            entries += self.get_sorted_entries(game_platform, filter_options)
        return entries

    # Get random entry
    def get_random_entry(self, filter_options = {}):
        game_platform = random.choice(self.get_sorted_platforms(filter_options))
        game_name = random.choice(self.get_sorted_names(game_platform, filter_options))
        game_entry = self.get_game(game_platform, game_name)
        return game_entry

    # Check if entry is missing data
    def is_entry_missing_data(self, game_platform, game_name, keys_to_check):
        game_entry = self.get_game(game_platform, game_name)
        for key_to_check in keys_to_check:
            if not key_to_check in game_entry.keys():
                return True
            if key_to_check in game_entry.keys() and game_entry[key_to_check] == "":
                return True
        return False

    # Check if missing data
    def is_missing_data(self, keys_to_check):
        for game_platform in self.get_sorted_platforms():
            for game_name in self.get_sorted_names(game_platform):
                if self.is_entry_missing_data(game_platform, game_name, keys_to_check):
                    return True
        return False

    # Merge with other metadata
    def merge_contents(self, other):
        import mergedeep
        self.game_database = mergedeep.merge(self.game_database, other.game_database)

    # Verify roms
    def verify_roms(self):
        for game_platform in self.get_sorted_platforms():
            for game_name in self.get_sorted_names(game_platform):
                print("Checking %s - %s ..." % (game_platform, game_name))
                game_entry = self.get_game(game_platform, game_name)
                virtual_file_path = game_entry[config.metadata_key_file]
                real_file_path = system.ResolveVirtualRomPath(virtual_file_path)
                if not os.path.exists(real_file_path):
                    print("File not found:\n%s" % virtual_file_path)
                    print("Verification of game %s in platform %s failed" % (game_name, game_platform))
                    sys.exit(1)

    # Sync assets
    def sync_assets(self):
        for game_platform in self.get_sorted_platforms():
            for game_name in self.get_sorted_names(game_platform):
                game_entry = self.get_game(game_platform, game_name)
                game_supercategory, game_category, game_subcategory = DeriveMetadataCategoriesFromPlatform(game_platform)
                for asset_type in config.asset_types_all:
                    game_asset_string = DeriveMetadataAssetString(game_name, asset_type)
                    game_asset_file = environment.GetSyncedGameAssetFile(game_category, game_subcategory, game_name, asset_type)
                    game_metadata_key = DeriveMetadataKeyFromAssetType(asset_type)
                    if asset_type in config.asset_types_min:
                        game_entry[game_metadata_key] = game_asset_string
                        continue
                    if os.path.isfile(game_asset_file):
                        game_entry[game_metadata_key] = game_asset_string
                    else:
                        if game_metadata_key in game_entry:
                            del game_entry[game_metadata_key]
                self.set_game(game_platform, game_name, game_entry)

    # Scan roms
    def scan_roms(self, rom_path, rom_category, rom_subcategory):
        for dir in system.BuildDirectoryList(rom_path):

            # Skip non-game folders
            if not IsGameFolder(dir):
                continue

            # Get info
            rom_name = system.GetDirectoryName(dir)
            rom_platform = DeriveMetadataPlatform(rom_category, rom_subcategory)

            # Get file
            rom_file = ""
            if rom_category == config.game_category_computer:
                letter = DeriveGameLetterFromName(rom_name)
                rom_file = os.path.join(config.token_rom_json_root, rom_category, rom_subcategory, letter, rom_name, rom_name + ".json")
            else:
                rom_file = os.path.join(config.token_rom_json_root, rom_category, rom_subcategory, rom_name, rom_name + ".json")
            rom_file = system.NormalizeFilePath(rom_file)

            # Get asset strings
            rom_boxfront = DeriveMetadataAssetString(rom_name, config.asset_type_boxfront)
            rom_boxback = DeriveMetadataAssetString(rom_name, config.asset_type_boxback)
            rom_background = DeriveMetadataAssetString(rom_name, config.asset_type_background)
            rom_screenshot = DeriveMetadataAssetString(rom_name, config.asset_type_screenshot)
            rom_video = DeriveMetadataAssetString(rom_name, config.asset_type_video)

            # Create new entry
            print("Found game: '%s' - '%s'" % (rom_platform, rom_name))
            game_entry = {}
            game_entry[config.metadata_key_platform] = rom_platform
            game_entry[config.metadata_key_game] = rom_name
            game_entry[config.metadata_key_file] = rom_file
            game_entry[config.metadata_key_boxfront] = rom_boxfront
            game_entry[config.metadata_key_boxback] = rom_boxback
            game_entry[config.metadata_key_background] = rom_background
            game_entry[config.metadata_key_screenshot] = rom_screenshot
            game_entry[config.metadata_key_video] = rom_video
            game_entry[config.metadata_key_players] = "1"
            game_entry[config.metadata_key_coop] = "No"
            self.add_game(game_entry)

    # Import from pegasus file
    def import_from_pegasus_file(self, pegasus_file):
        with open(pegasus_file, "r", encoding="utf8") as file:
            data = file.read()

            # Read header
            collection_platform = ""
            for line in data.split("\n"):
                if line.startswith("collection:"):
                    collection_platform = line.replace("collection:", "").strip()
                    break

            # Read game entries
            for token in data.split("\n\n"):

                # Create new entry
                game_entry = {}
                game_entry[config.metadata_key_platform] = collection_platform
                in_description_section = False

                # Parse entry tokens
                for line in token.split("\n"):

                    # Game
                    if line.startswith("game:"):
                        in_description_section = False
                        game_entry[config.metadata_key_game] = line.replace("game:", "").strip()

                    # File
                    elif line.startswith("file:"):
                        in_description_section = False
                        game_entry[config.metadata_key_file] = line.replace("file:", "").strip()

                    # Developer
                    elif line.startswith("developer:"):
                        in_description_section = False
                        game_entry[config.metadata_key_developer] = line.replace("developer:", "").strip()

                    # Publisher
                    elif line.startswith("publisher:"):
                        in_description_section = False
                        game_entry[config.metadata_key_publisher] = line.replace("publisher:", "").strip()

                    # Genre
                    elif line.startswith("genre:"):
                        in_description_section = False
                        game_entry[config.metadata_key_genre] = line.replace("genre:", "").strip()

                    # Tag
                    elif line.startswith("tag:"):
                        in_description_section = False
                        game_entry[config.metadata_key_tag] = line.replace("tag:", "").strip()

                    # Description
                    elif line.startswith("description:"):
                        in_description_section = True
                        game_entry[config.metadata_key_description] = []
                    elif line.startswith("  ") and in_description_section:
                        game_entry[config.metadata_key_description].append(line.strip())

                    # Release
                    elif line.startswith("release:"):
                        in_description_section = False
                        game_entry[config.metadata_key_release] = line.replace("release:", "").strip()

                    # Players
                    elif line.startswith("players:"):
                        in_description_section = False
                        game_entry[config.metadata_key_players] = line.replace("players:", "").strip()

                    # Boxfront
                    elif line.startswith("assets.boxfront:"):
                        in_description_section = False
                        game_entry[config.metadata_key_boxfront] = line.replace("assets.boxfront:", "").strip()

                    # Boxback
                    elif line.startswith("assets.boxback:"):
                        in_description_section = False
                        game_entry[config.metadata_key_boxback] = line.replace("assets.boxback:", "").strip()

                    # Background
                    elif line.startswith("assets.background:"):
                        in_description_section = False
                        game_entry[config.metadata_key_background] = line.replace("assets.background:", "").strip()

                    # Screenshot
                    elif line.startswith("assets.screenshot:"):
                        in_description_section = False
                        game_entry[config.metadata_key_screenshot] = line.replace("assets.screenshot:", "").strip()

                    # Video
                    elif line.startswith("assets.video:"):
                        in_description_section = False
                        game_entry[config.metadata_key_video] = line.replace("assets.video:", "").strip()

                    # Co-op
                    elif line.startswith("x-co-op:"):
                        in_description_section = False
                        game_entry[config.metadata_key_coop] = line.replace("x-co-op:", "").strip()

                # Check minimum keys
                has_minimum_keys = True
                for key in GetMinimumMetadataKeys():
                    if not key in game_entry:
                        has_minimum_keys = False

                # Add new entry
                if has_minimum_keys:
                    self.add_game(game_entry)

    # Import from gamelist file
    def import_from_gamelist_file(self, gamelist_file):
        with open(gamelist_file, "r", encoding="utf8") as file:
            for line in file.readlines():
                tokens = line.strip().split(" || ")
                if len(tokens) != 3:
                   continue
                game_entry = {}
                game_entry[config.metadata_key_platform] = tokens[0]
                game_entry[config.metadata_key_game] = tokens[1]
                game_entry[config.metadata_key_file] = tokens[2]
                game_entry[config.metadata_key_players] = "1"
                game_entry[config.metadata_key_coop] = "No"
                self.add_game(game_entry)

    # Import from metadata file
    def import_from_metadata_file(self, metadata_file, metadata_format):
        if metadata_format == "gamelist":
            self.import_from_gamelist_file(metadata_file)
        elif metadata_format == "pegasus":
            self.import_from_pegasus_file(metadata_file)

    # Export to pegasus file
    def export_to_pegasus_file(self, pegasus_file, append_existing = False):
        file_mode = "a" if append_existing else "w"
        with open(pegasus_file, file_mode, encoding="utf8", newline="\n") as file:
            for game_platform in self.get_sorted_platforms():

                # Write header
                file.write("collection: %s\n" % game_platform)
                file.write("launch: {env.JB_LAUNCHROM_PROGRAM} -l \"%s\" {file.path}\n" % game_platform)
                file.write("\n\n")

                # Write each entry
                for game_entry in self.get_sorted_entries(game_platform):

                    # Game
                    if config.metadata_key_game in game_entry:
                        file.write("game: " + game_entry[config.metadata_key_game] + "\n")

                    # File
                    if config.metadata_key_file in game_entry:
                        file.write("file: " + game_entry[config.metadata_key_file] + "\n")

                    # Developer
                    if config.metadata_key_developer in game_entry:
                        file.write("developer: " + game_entry[config.metadata_key_developer] + "\n")

                    # Publisher
                    if config.metadata_key_publisher in game_entry:
                        file.write("publisher: " + game_entry[config.metadata_key_publisher] + "\n")

                    # Genre
                    if config.metadata_key_genre in game_entry:
                        file.write("genre: " + game_entry[config.metadata_key_genre] + "\n")

                    # Tag
                    if config.metadata_key_tag in game_entry:
                        file.write("tag: " + game_entry[config.metadata_key_tag] + "\n")

                    # Description
                    if config.metadata_key_description in game_entry:
                        file.write("description:\n")
                        for desc_line in game_entry[config.metadata_key_description]:
                            file.write("  " + desc_line + "\n")

                    # Release
                    if config.metadata_key_release in game_entry:
                        file.write("release: " + game_entry[config.metadata_key_release] + "\n")

                    # Players
                    if config.metadata_key_players in game_entry:
                        file.write("players: " + game_entry[config.metadata_key_players] + "\n")

                    # Boxfront
                    if config.metadata_key_boxfront in game_entry:
                        file.write("assets.boxfront: " + game_entry[config.metadata_key_boxfront] + "\n")

                    # Boxback
                    if config.metadata_key_boxback in game_entry:
                        file.write("assets.boxback: " + game_entry[config.metadata_key_boxback] + "\n")

                    # Background
                    if config.metadata_key_background in game_entry:
                        file.write("assets.background: " + game_entry[config.metadata_key_background] + "\n")

                    # Screenshot
                    if config.metadata_key_screenshot in game_entry:
                        file.write("assets.screenshot: " + game_entry[config.metadata_key_screenshot] + "\n")

                    # Video
                    if config.metadata_key_video in game_entry:
                        file.write("assets.video: " + game_entry[config.metadata_key_video] + "\n")

                    # Co-op
                    if config.metadata_key_coop in game_entry:
                        file.write("x-co-op: " + game_entry[config.metadata_key_coop] + "\n")

                    # Divider
                    file.write("\n\n")

    # Export to gamelist file
    def export_to_gamelist_file(self, gamelist_file, append_existing = False):
        file_mode = "a" if append_existing else "w"
        with open(gamelist_file, file_mode, encoding="utf8", newline="\n") as file:
            for game_platform in self.get_sorted_platforms():
                for game_entry in self.get_sorted_entries(game_platform):
                    game_name = game_entry[config.metadata_key_game]
                    game_file = game_entry[config.metadata_key_file]
                    file.write("%s || %s || %s\n" % (game_platform, game_name, game_file))

    # Export to metadata file
    def export_to_metadata_file(self, metadata_file, metadata_format, append_existing = False):
        if metadata_format == "gamelist":
            self.export_to_gamelist_file(metadata_file, append_existing)
        elif metadata_format == "pegasus":
            self.export_to_pegasus_file(metadata_file, append_existing)

# Get metadata formats
def GetMetadataFormats():
    return [config.metadata_format_gamelist, config.metadata_format_pegasus]

# Get metadata supercategories
def GetMetadataSupercategories():
    return [config.game_supercategory_roms, config.game_supercategory_dlc, config.game_supercategory_updates]

# Get metadata default supercategory
def GetMetadataDefaultSupercategory():
    return config.game_supercategory_roms

# Get metadata categories
def GetMetadataCategories():
    return list(config.game_platforms.keys())

# Get metadata subcategories
def GetMetadataSubcategories(game_category = None, filter_options = {}):
    potential_subcategories = []
    if game_category and game_category in config.game_platforms.keys():
        potential_subcategories = config.game_platforms[game_category]
    else:
        for game_category in config.game_platforms.keys():
            potential_subcategories += config.game_platforms[game_category]
    subcategories = []
    for game_subcategory in potential_subcategories:
        only_launchable = GetFilterOption(filter_options, config.filter_launchable_only)
        no_launcher_set = (DeriveMetadataPlatform(game_category, game_subcategory) in config.no_launcher_platforms)
        if only_launchable and no_launcher_set:
            continue
        subcategories.append(game_subcategory)
    return subcategories

# Get filter option
def GetFilterOption(options, key):
    if key in config.filter_bool_keys:
        if options and key in options:
            return bool(options[key])
        return False
    return None

# Check if subcategory is a valid child of the given category
def IsValidCategoryPair(game_category, game_subcategory):
    if not game_category in GetMetadataCategories():
        return False
    if not game_subcategory in GetMetadataSubcategories(game_category):
        return False
    return True

# Get minimum metadata keys
def GetMinimumMetadataKeys():
    return [
        config.metadata_key_platform,
        config.metadata_key_game,
        config.metadata_key_file,
        config.metadata_key_players
    ]

# Get missing metadata keys
def GetMissingMetadataKeys():
    return [
        config.metadata_key_description,
        config.metadata_key_developer,
        config.metadata_key_publisher,
        config.metadata_key_genre,
        config.metadata_key_players,
        config.metadata_key_coop,
        config.metadata_key_release
    ]

# Get replaceable metadata keys
def GetReplaceableMetadataKeys():
    return [
        config.metadata_key_description,
        config.metadata_key_genre,
        config.metadata_key_tag,
        config.metadata_key_developer,
        config.metadata_key_publisher,
        config.metadata_key_players,
        config.metadata_key_coop,
        config.metadata_key_release
    ]

# Check if file is a metadata file
def IsMetadataFile(metadata_file, metadata_format):
    if metadata_format == config.metadata_format_pegasus:
        return metadata_file.endswith("metadata.pegasus.txt")
    elif metadata_format == config.metadata_format_gamelist:
        if system.GetFilenameBasename(metadata_file) in GetMetadataSubcategories():
            return True
    return False

# Check if folder is a game folder
def IsGameFolder(rom_directory):
    potential_folder = system.GetDirectoryName(rom_directory)
    is_versioned = "(v" in potential_folder
    is_eshop = "(eShop)" in potential_folder
    if is_versioned and is_eshop:
        return False
    if potential_folder.endswith(")"):
        return True
    return False

# Choose random game
def ChooseRandomGame(rom_category = None, rom_subcategory = None, filter_options = {}):
    if not rom_category:
        rom_category = random.choice(GetMetadataCategories())
    if not rom_subcategory:
        rom_subcategory = random.choice(GetMetadataSubcategories(rom_category, filter_options))
    if not IsValidCategoryPair(rom_category, rom_subcategory):
        return None
    metadata_file = DeriveMetadataFile(rom_category, rom_subcategory, config.metadata_format_gamelist)
    metadata_obj = Metadata()
    metadata_obj.import_from_gamelist_file(metadata_file)
    return metadata_obj.get_random_entry(filter_options)

# Derive game name from path
def DeriveGameNameFromPath(rom_path):
    rom_dir = system.GetFilenameDirectory(rom_path)
    rom_basename = os.path.basename(rom_dir)
    if not rom_basename.endswith(")"):
        return ""
    return rom_basename

# Derive game letter from name
def DeriveGameLetterFromName(rom_name):
    letter = ""
    if len(rom_name):
        letter = rom_name[0].upper()
    if letter.isnumeric():
        letter = config.general_numeric_folder
    return letter

# Derive game save format from category
def DeriveGameSaveFormatFromCategory(rom_category):
    if rom_category == config.game_category_computer:
        return config.save_format_general
    return None

# Derive platform from rom category/subcategory
def DeriveMetadataPlatform(rom_category, rom_subcategory):
    game_platform = rom_subcategory
    if rom_category == config.game_category_computer:
        game_platform = rom_category + " - " + rom_subcategory
    return game_platform

# Derive categories from rom platform
def DeriveMetadataCategoriesFromPlatform(rom_platform):
    if not rom_platform:
        return (None, None, None)
    derived_rom_category = ""
    derived_rom_subcategory = ""
    if rom_platform.startswith(config.game_category_computer):
        derived_rom_category = config.game_category_computer
        derived_rom_subcategory = rom_platform.replace(config.game_category_computer + " - ", "")
    elif rom_platform.startswith(config.game_category_microsoft):
        derived_rom_category = config.game_category_microsoft
        derived_rom_subcategory = rom_platform
    elif rom_platform.startswith(config.game_category_nintendo):
        derived_rom_category = config.game_category_nintendo
        derived_rom_subcategory = rom_platform
    elif rom_platform.startswith(config.game_category_sony):
        derived_rom_category = config.game_category_sony
        derived_rom_subcategory = rom_platform
    else:
        derived_rom_category = config.game_category_other
        derived_rom_subcategory = rom_platform
    return (config.game_supercategory_roms, derived_rom_category, derived_rom_subcategory)

# Derive categories from file
def DeriveMetadataCategoriesFromFile(input_file):

    # Check file
    if not system.IsPathValid(input_file):
        return (None, None, None)

    # Get source directory and basename
    source_dir = system.GetFilenameDirectory(system.NormalizeFilePath(input_file))
    base_name = system.GetFilenameBasename(system.NormalizeFilePath(input_file))

    # Get possible root dirs
    root_dirs = [
        system.NormalizeFilePath(environment.GetGamingStorageRootDir()),
        system.NormalizeFilePath(environment.GetGamingLocalCacheRootDir()),
        system.NormalizeFilePath(environment.GetGamingRemoteCacheRootDir()),
        system.NormalizeFilePath(environment.GetJsonMetadataRootDir())
    ]

    # Get relative source directory
    relative_source_dir = source_dir
    for root_dir in root_dirs:
        relative_source_dir = system.RebaseFilePath(relative_source_dir, root_dir, "")

    # Derive supercategory
    derived_supercategory = ""
    for possible_supercategory in config.game_supercategories:
        if relative_source_dir.startswith(possible_supercategory):
            derived_supercategory = possible_supercategory
    if len(derived_supercategory) == 0:
        return (None, None, None)

    # Get relative path
    relative_file_path = relative_source_dir[relative_source_dir.index(derived_supercategory) + len(derived_supercategory):].strip(os.sep)
    relative_file_path_tokens = relative_file_path.split(os.sep)
    if len(relative_file_path_tokens) < 2:
        return (None, None, None)

    # Get derived category and subcategory
    derived_category = ""
    derived_subcategory = relative_file_path_tokens[1]
    if relative_file_path.startswith(config.game_category_computer):
        derived_category = config.game_category_computer
    elif relative_file_path.startswith(config.game_category_microsoft):
        derived_category = config.game_category_microsoft
    elif relative_file_path.startswith(config.game_category_nintendo):
        derived_category = config.game_category_nintendo
    elif relative_file_path.startswith(config.game_category_sony):
        derived_category = config.game_category_sony
    else:
        derived_category = config.game_category_other
    return (derived_supercategory, derived_category, derived_subcategory)

# Derive metadata file from game category/subcategory
def DeriveMetadataFile(game_category, game_subcategory, metadata_format):
    game_file = ""
    if metadata_format == config.metadata_format_gamelist:
        game_file = environment.GetGameListMetadataFile(game_category, game_subcategory)
    elif metadata_format == config.metadata_format_pegasus:
        game_file = environment.GetPegasusMetadataFile(game_category, game_subcategory)
    return game_file

# Derive metadata key from asset type
def DeriveMetadataKeyFromAssetType(asset_type):
    if asset_type == config.asset_type_background:
        return config.metadata_key_background
    elif asset_type == config.asset_type_boxback:
        return config.metadata_key_boxback
    elif asset_type == config.asset_type_boxfront:
        return config.metadata_key_boxfront
    elif asset_type == config.asset_type_label:
        return config.metadata_key_label
    elif asset_type == config.asset_type_screenshot:
        return config.metadata_key_screenshot
    elif asset_type == config.asset_type_video:
        return config.metadata_key_video
    return None

# Derive metadata asset string
def DeriveMetadataAssetString(game_name, asset_type):
    asset_ext = config.asset_type_extensions[asset_type]
    asset_string = "%s/%s%s" % (asset_type, game_name, asset_ext)
    return asset_string

# Find best suited game file
def FindBestGameFile(game_directory):
    game_file_entries = []
    for obj in system.GetDirectoryContents(game_directory):
        obj_path = os.path.join(game_directory, obj)
        if os.path.isfile(obj_path):
            game_file_entry = {}
            game_file_entry["file"] = os.path.abspath(obj_path)
            game_file_entry["weight"] = config.gametype_weight_else
            for key in config.gametype_weights.keys():
                if obj.endswith(key):
                    game_file_entry["weight"] = config.gametype_weights[key]
                    break
            game_file_entries.append(game_file_entry)
    game_file = ""
    for game_file_entry in sorted(game_file_entries, key=lambda d: d["weight"]):
        game_file = game_file_entry["file"]
        break
    return game_file

# Convert metadata name to regular name
def ConvertMetadataNameToRegularName(name):
    regular_name = name
    if ", The " in regular_name:
        regular_name = regular_name.replace(", The ", " ")
        regular_name = "The " + regular_name
    if ", A " in regular_name:
        regular_name = regular_name.replace(", A ", " ")
        regular_name = "A " + regular_name
    regular_name = re.sub(r"\((.*?)\)", "", regular_name).strip()
    return regular_name

# Convert raw game description to metadata format
def ConvertRawDescriptionToMetadataFormat(raw_description):

    # Replace special characters
    new_description = raw_description.strip()
    new_description = new_description.replace("“", "\"")
    new_description = new_description.replace("”", "\"")
    new_description = new_description.replace("’", "'")
    new_description = new_description.replace("ʻ", "'")
    new_description = new_description.replace("‘", "'")
    new_description = new_description.replace("…", "...")
    new_description = new_description.replace("•", "*")
    new_description = new_description.replace("—", "-")
    new_description = new_description.replace("–", "-")

    # Replace leftover html
    new_description = new_description.replace("<span>", " ")
    new_description = new_description.replace("</span>", " ")
    new_description = new_description.replace("&lt;", " ")
    new_description = new_description.replace("&gt;", " ")
    new_description = new_description.replace("&quot;", " ")
    new_description = new_description.replace("&amp;", " ")
    new_description = new_description.replace("amp;", " ")

    # Replace non-ascii characters
    cleared_description = new_description.encode("ascii", "ignore")
    new_description = cleared_description.decode()

    # Final cleanup
    new_description = new_description.replace("()", "")

    # Create metadata lines
    metadata_lines = []
    original_lines = new_description.split("\n")
    for i in range(0, len(original_lines)):
        original_line = original_lines[i].strip()
        for wrapped_line in textwrap.wrap(original_line, width=80):
            metadata_lines.append(wrapped_line)
        if i < len(original_lines) - 1:
            metadata_lines.append(".")

    # Remove duplicate adjacent lines
    result = []
    for metadata_line in metadata_lines:
        if len(result) == 0 or metadata_line != result[-1]:
            result.append(metadata_line)
    return result

# Collect metadata from TheGamesDB
def CollectMetadataFromTGDB(web_driver, game_platform, game_name, select_automatically = False, ignore_unowned = False):

    # Get keywords name
    natural_name = ConvertMetadataNameToRegularName(game_name)
    keywords_name = urllib.parse.quote_plus(natural_name.strip())

    # Metadata result
    metadata_result = {}

    # Get platform id
    thegamesdb_platform_id = config.thegamesdb_platform_ids[game_platform]

    # Go to the search page and pull the results
    try:
        web_driver.get("https://thegamesdb.net/search.php?name=" + keywords_name + "&platform_id%5B%5D=" + thegamesdb_platform_id)
    except:
        return None

    # Select an entry automatically
    if select_automatically:

        # Find the root container element
        section_search_result = webpage.WaitForPageElement(web_driver, class_name = "container-fluid", wait_time = 5)
        if not section_search_result:
            return None

        # Score each potential title compared to the original title
        scores_list = []
        game_cards = webpage.GetElement(section_search_result, class_name = "card-footer", all_elements = True)
        if game_cards:
            for game_card in game_cards:
                game_card_text = webpage.GetElementText(game_card)

                # Get potential title
                potential_title = ""
                if game_card_text:
                    for game_card_text_token in game_card_text.split("\n"):
                        potential_title = game_card_text_token
                        break

                # Get comparison score
                from fuzzywuzzy import fuzz
                score_entry = {}
                score_entry["node"] = game_card
                score_entry["ratio"] = fuzz.ratio(natural_name, potential_title)
                scores_list.append(score_entry)

        # Click on the highest score node
        for score_entry in sorted(scores_list, key=lambda d: d["ratio"], reverse=True):
            webpage.ClickElement(score_entry["node"])
            break

        # Check if the url has changed
        if webpage.IsUrlLoaded(web_driver, "https://thegamesdb.net/search.php?name="):
            return None

    # Look for game description
    section_game_description = webpage.WaitForPageElement(web_driver, class_name = "game-overview")
    if not section_game_description:
        return None

    # Grab the description text
    raw_game_description = webpage.GetElementText(section_game_description)

    # Convert description to metadata format
    if raw_game_description:
        metadata_result[config.metadata_key_description] = ConvertRawDescriptionToMetadataFormat(raw_game_description)

    # Look for game details
    for section_game_details in webpage.GetElement(web_driver, class_name = "card-body", all_elements = True):
        for element_paragraph in webpage.GetElement(section_game_details, tag_name = "p", all_elements = True):
            element_text = webpage.GetElementText(element_paragraph)
            if not element_text:
                continue

            # Genre
            if "Genre(s):" in element_text:
                metadata_result[config.metadata_key_genre] = element_text.replace("Genre(s):", "").replace(" | ", ";").strip()

            # Co-op
            if "Co-op:" in element_text:
                metadata_result[config.metadata_key_coop] = element_text.replace("Co-op:", "").strip()

            # Developer
            if "Developer(s):" in element_text:
                metadata_result[config.metadata_key_developer] = element_text.replace("Developer(s):", "").strip()

            # Publisher
            if "Publishers(s):" in element_text:
                metadata_result[config.metadata_key_publisher] = element_text.replace("Publishers(s):", "").strip()

            # Players
            if "Players:" in element_text:
                metadata_result[config.metadata_key_players] = element_text.replace("Players:", "").strip()

            # Release
            if "ReleaseDate:" in element_text:
                metadata_result[config.metadata_key_release] = element_text.replace("ReleaseDate:", "").strip()

    # Return metadata
    time.sleep(5)
    return metadata_result

# Collect metadata from GameFAQs
def CollectMetadataFromGameFAQS(web_driver, game_platform, game_name, select_automatically = False, ignore_unowned = False):

    # Get keywords name
    natural_name = ConvertMetadataNameToRegularName(game_name)
    keywords_name = urllib.parse.quote_plus(natural_name.strip())

    # Metadata result
    metadata_result = {}

    # Go to the search page and pull the results
    try:
        web_driver.get("https://gamefaqs.gamespot.com/search_advanced?game=" + keywords_name)
    except:
        return None

    # Look for game description
    section_game_description = webpage.WaitForPageElement(web_driver, class_name = "game_desc")
    if not section_game_description:
        return None

    # Grab the description text
    raw_game_description = webpage.GetElementText(section_game_description)

    # Click the "more" button if it's present
    if "more »" in raw_game_description:
        element_game_description_more = webpage.GetElement(web_driver, link_text = "more »")
        if element_game_description_more:
            webpage.ClickElement(element_game_description_more)

    # Re-grab the description text
    raw_game_description = webpage.GetElementText(section_game_description)

    # Convert description to metadata format
    if raw_game_description:
        metadata_result[config.metadata_key_description] = ConvertRawDescriptionToMetadataFormat(raw_game_description)

    # Look for game details
    for section_game_details in webpage.GetElement(web_driver, class_name = "content", all_elements = True):
        element_text = webpage.GetElementText(section_game_details)
        if not element_text:
            continue

        # Genre
        if element_text.startswith("Genre:"):
            metadata_result[config.metadata_key_genre] = element_text.replace("Genre:", "").replace(" » ", ";").strip()

        # Developer
        elif element_text.startswith("Developer:"):
            metadata_result[config.metadata_key_developer] = element_text.replace("Developer:", "").strip()

        # Publisher
        elif element_text.startswith("Publisher:"):
            metadata_result[config.metadata_key_publisher] = element_text.replace("Publisher:", "").strip()

        # Developer/Publisher
        elif element_text.startswith("Developer/Publisher:"):
            metadata_result[config.metadata_key_developer] = element_text.replace("Developer/Publisher:", "").strip()
            metadata_result[config.metadata_key_publisher] = element_text.replace("Developer/Publisher:", "").strip()

        # Release/First Released
        elif element_text.startswith("Release:") or element_text.startswith("First Released:"):
            import dateutil.parser
            release_text = ""
            if element_text.startswith("Release:"):
                release_text = element_text.replace("Release:", "").strip()
            elif element_text.startswith("First Released:"):
                release_text = element_text.replace("First Released:", "").strip()
            release_time = dateutil.parser.parse(release_text)
            metadata_result[config.metadata_key_release] = release_time.strftime("%Y-%m-%d")

    # Return metadata
    return metadata_result

# Collect metadata from Itch.io
def CollectMetadataFromItchio(web_driver, game_platform, game_name, select_automatically = False, ignore_unowned = False):

    # Get keywords name
    natural_name = ConvertMetadataNameToRegularName(game_name)
    keywords_name = urllib.parse.quote_plus(natural_name.strip())

    # Metadata result
    metadata_result = {}

    # Check if cookie exists first
    if os.path.exists(config.itchio_cookie_filename):

        # Load the main page
        try:
            web_driver.get("https://itch.io")
        except:
            return None

        # Load cookie
        webpage.LoadCookie(web_driver, config.itchio_cookie_filename)

    # Otherwise, create one
    else:

        # Log into itch.io first
        try:
            web_driver.get("https://itch.io/login")
        except:
            return None

        # Look for my feed
        section_my_feed = webpage.WaitForPageElement(web_driver, link_text = "My feed")
        if not section_my_feed:
            return None

        # Save cookie
        webpage.SaveCookie(web_driver, config.itchio_cookie_filename)

    # Go to the search page and pull the results
    try:
        web_driver.get("https://itch.io/search?q=" + keywords_name)
    except:
        return None

    # Select an entry automatically
    if select_automatically:
        section_search_result = webpage.WaitForPageElement(web_driver, class_name = "game_cell")
        if section_search_result:
            webpage.ClickElement(section_search_result)
        while webpage.GetCurrentPageUrl(web_driver).startswith("https://itch.io/search?q="):
            time.sleep(1)

    # Ignore unowned games
    if ignore_unowned:
        section_game_purchased = webpage.WaitForPageElement(web_driver, class_name = "purchase_banner_inner", wait_time = 3)
        if not section_game_purchased:
            return None

    # Look for game description
    section_game_description = webpage.WaitForPageElement(web_driver, class_name = "formatted_description")
    if not section_game_description:
        return None

    # Look for game information
    section_game_information = webpage.WaitForPageElement(web_driver, class_name = "more_information_toggle")
    if not section_game_information:
        return None

    # Grab the description text
    raw_game_description = webpage.GetElementText(section_game_description)

    # Convert description to metadata format
    if raw_game_description:
        metadata_result[config.metadata_key_description] = ConvertRawDescriptionToMetadataFormat(raw_game_description)

    # Grab the information text
    raw_game_information = webpage.GetElementText(section_game_information)

    # Click the "More information" button if it's present
    if "More information" in raw_game_information:
        element_game_info_more = webpage.GetElement(web_driver, link_text = "More information")
        if element_game_info_more:
            webpage.ClickElement(element_game_info_more)

    # Wait for more information to load
    time.sleep(3)

    # Look for game details
    section_game_details = webpage.GetElement(web_driver, class_name = "game_info_panel_widget")
    if section_game_details:

        # Grab the information text
        raw_game_details = webpage.GetElementText(section_game_details)
        for game_detail_line in raw_game_details.split("\n"):

            # Release
            if game_detail_line.startswith("Release date"):
                release_text = game_detail_line.replace("Release date", "").strip()
                release_time = datetime.datetime.strptime(release_text, "%b %d, %Y")
                metadata_result[config.metadata_key_release] = release_time.strftime("%Y-%m-%d")
            if game_detail_line.startswith("Published"):
                release_text = game_detail_line.replace("Published", "").strip()
                release_time = datetime.datetime.strptime(release_text, "%b %d, %Y")
                metadata_result[config.metadata_key_release] = release_time.strftime("%Y-%m-%d")

            # Developer/publisher
            elif game_detail_line.startswith("Authors"):
                author_text = game_detail_line.replace("Authors", "").strip()
                metadata_result[config.metadata_key_developer] = author_text
                metadata_result[config.metadata_key_publisher] = author_text
            elif game_detail_line.startswith("Author"):
                author_text = game_detail_line.replace("Author", "").strip()
                metadata_result[config.metadata_key_developer] = author_text
                metadata_result[config.metadata_key_publisher] = author_text

            # Genre
            elif game_detail_line.startswith("Genre"):
                metadata_result[config.metadata_key_genre] = game_detail_line.replace("Genre", "").strip().replace(", ", ";")

    # Return metadata
    return metadata_result
