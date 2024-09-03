# Imports
import os, os.path
import sys
import re
import urllib.parse
import datetime
import time
import textwrap
import random

# Local imports
import config
import system
import webpage
import platforms
import environment
import gameinfo
import youtube
import asset

# Metadata entry class
class MetadataEntry:

    # Constructor
    def __init__(self):
        self.game_entry = {}

    # Has minimum keys
    def has_minimum_keys(self):
        for key in config.metadata_keys_minimum:
            if not key in self.game_entry.keys():
                return False
        return True

    # Determine if key is set
    def is_key_set(self, key):
        return key in self.game_entry.keys()

    # Get value
    def get_value(self, key):
        return self.game_entry[key]

    # Set value
    def set_value(self, key, value):
        self.game_entry[key] = value

    # Delete value
    def delete_value(self, key):
        del self.game_entry[key]

    # Merge data
    def merge(self, other):
        return system.MergeDictionaries(
            dict1 = other.game_entry,
            dict2 = self.game_entry,
            merge_type = config.merge_type_safeadditive)

    # Game name
    def get_game(self):
        return self.get_value(config.metadata_key_game)
    def set_game(self, value):
        self.set_value(config.metadata_key_game, value)

    # Game platform
    def get_platform(self):
        return self.get_value(config.metadata_key_platform)
    def set_platform(self, value):
        self.set_value(config.metadata_key_platform, value)

    # Game supercategory
    def get_supercategory(self):
        return self.get_value(config.metadata_key_supercategory)
    def set_supercategory(self, value):
        self.set_value(config.metadata_key_supercategory, value)

    # Game category
    def get_category(self):
        return self.get_value(config.metadata_key_category)
    def set_category(self, value):
        self.set_value(config.metadata_key_category, value)

    # Game subcategory
    def get_subcategory(self):
        return self.get_value(config.metadata_key_subcategory)
    def set_subcategory(self, value):
        self.set_value(config.metadata_key_subcategory, value)

    # Game file
    def get_file(self):
        return self.get_value(config.metadata_key_file)
    def set_file(self, value):
        self.set_value(config.metadata_key_file, value)

    # Game description
    def get_description(self):
        return self.get_value(config.metadata_key_description)
    def set_description(self, value):
        self.set_value(config.metadata_key_description, value)

    # Game genre
    def get_genre(self):
        return self.get_value(config.metadata_key_genre)
    def set_genre(self, value):
        self.set_value(config.metadata_key_genre, value)

    # Game coop
    def get_coop(self):
        return self.get_value(config.metadata_key_coop)
    def set_coop(self, value):
        self.set_value(config.metadata_key_coop, value)

    # Game playable
    def get_playable(self):
        return self.get_value(config.metadata_key_playable)
    def set_playable(self, value):
        self.set_value(config.metadata_key_playable, value)

    # Game developer
    def get_developer(self):
        return self.get_value(config.metadata_key_developer)
    def set_developer(self, value):
        self.set_value(config.metadata_key_developer, value)

    # Game publisher
    def get_publisher(self):
        return self.get_value(config.metadata_key_publisher)
    def set_publisher(self, value):
        self.set_value(config.metadata_key_publisher, value)

    # Game players
    def get_players(self):
        return self.get_value(config.metadata_key_players)
    def set_players(self, value):
        self.set_value(config.metadata_key_players, value)

    # Game release
    def get_release(self):
        return self.get_value(config.metadata_key_release)
    def set_release(self, value):
        self.set_value(config.metadata_key_release, value)

    # Game background
    def get_background(self):
        return self.get_value(config.metadata_key_background)
    def set_background(self, value):
        self.set_value(config.metadata_key_background, value)

    # Game box back
    def get_boxback(self):
        return self.get_value(config.metadata_key_boxback)
    def set_boxback(self, value):
        self.set_value(config.metadata_key_boxback, value)

    # Game box front
    def get_boxfront(self):
        return self.get_value(config.metadata_key_boxfront)
    def set_boxfront(self, value):
        self.set_value(config.metadata_key_boxfront, value)

    # Game label
    def get_label(self):
        return self.get_value(config.metadata_key_label)
    def set_label(self, value):
        self.set_value(config.metadata_key_label, value)

    # Game screenshot
    def get_screenshot(self):
        return self.get_value(config.metadata_key_screenshot)
    def set_screenshot(self, value):
        self.set_value(config.metadata_key_screenshot, value)

    # Game video
    def get_video(self):
        return self.get_value(config.metadata_key_video)
    def set_video(self, value):
        self.set_value(config.metadata_key_video, value)

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
        game_supercategory, game_category, game_subcategory = gameinfo.DeriveGameCategoriesFromPlatform(game_platform)
        game_entry.set_supercategory(game_supercategory)
        game_entry.set_category(game_category)
        game_entry.set_subcategory(game_subcategory)

        # Add platform if not already there
        if not game_platform in self.game_database.keys():
            self.game_database[game_platform] = {}

        # Add entry
        if game_name in self.game_database[game_platform]:
            self.game_database[game_platform][game_name].merge(game_entry)
        else:
            self.game_database[game_platform][game_name] = game_entry

    # Get game entry
    def get_game(self, game_platform, game_name):
        return self.game_database[game_platform][game_name]

    # Set game entry
    def set_game(self, game_platform, game_name, game_entry):
        self.game_database[game_platform][game_name] = game_entry

    # Get sorted platforms
    def get_sorted_platforms(self):
        potential_platforms = []
        for platform in self.game_database.keys():
            potential_platforms.append(platform)
        return sorted(potential_platforms)

    # Get sorted names within a platform
    def get_sorted_names(self, game_platform):
        if not game_platform in self.game_database:
            return []
        potential_names = []
        for name in self.game_database[game_platform].keys():
            potential_names.append(name)
        return sorted(potential_names)

    # Get all sorted names
    def get_all_sorted_names(self):
        names = []
        for game_platform in self.get_sorted_platforms():
            names += self.get_sorted_names(game_platform)
        return names

    # Get sorted entries
    def get_sorted_entries(self, game_platform):
        entries = []
        for game_name in self.get_sorted_names(game_platform):
            entries.append(self.get_game(game_platform, game_name))
        return entries

    # Get all sorted entries
    def get_all_sorted_entries(self):
        entries = []
        for game_platform in self.get_sorted_platforms():
            entries += self.get_sorted_entries(game_platform)
        return entries

    # Get random entry
    def get_random_entry(self):
        game_platform = random.choice(self.get_sorted_platforms())
        game_name = random.choice(self.get_sorted_names(game_platform))
        game_entry = self.get_game(game_platform, game_name)
        return game_entry

    # Check if entry is missing data
    def is_entry_missing_data(self, game_platform, game_name, keys_to_check):
        game_entry = self.get_game(game_platform, game_name)
        for key_to_check in keys_to_check:
            if not game_entry.is_key_set(key_to_check):
                return True
            if game_entry.is_key_set(key_to_check) and game_entry.get_value(key_to_check) == "":
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
        self.game_database = system.MergeDictionaries(
            dict1 = self.game_database,
            dict2 = other.game_database,
            merge_type = config.merge_type_safeadditive)

    # Verify roms
    def verify_roms(self, verbose = False, exit_on_failure = False):
        for game_platform in self.get_sorted_platforms():
            for game_name in self.get_sorted_names(game_platform):
                if verbose:
                    system.Log("Checking %s - %s ..." % (game_platform, game_name))

                # Get game entry
                game_entry = self.get_game(game_platform, game_name)

                # Check file paths
                file_path_relative = game_entry.get_file()
                file_path_real = os.path.join(environment.GetJsonRomsMetadataRootDir(), file_path_relative)
                if not os.path.exists(file_path_real):
                    system.LogError("File not found:\n%s" % file_path_relative)
                    system.LogErrorAndQuit("Verification of game %s in platform %s failed" % (game_name, game_platform))

    # Sync assets
    def sync_assets(self, verbose = False, exit_on_failure = False):
        for game_platform in self.get_sorted_platforms():
            for game_name in self.get_sorted_names(game_platform):
                if verbose:
                    system.Log("Checking %s - %s ..." % (game_platform, game_name))

                # Get game entry
                game_entry = self.get_game(game_platform, game_name)
                game_category = game_entry.get_category()
                game_subcategory = game_entry.get_subcategory()

                # Check all asset types
                for asset_type in config.asset_types_all:
                    game_asset_string = gameinfo.DeriveGameAssetPathFromName(game_name, asset_type)
                    game_asset_file = environment.GetLockerGamingAssetFile(game_category, game_subcategory, game_name, asset_type)

                    # Get metadata key associated with the asset type
                    game_metadata_key = None
                    if asset_type == config.asset_type_background:
                        game_metadata_key = config.metadata_key_background
                    elif asset_type == config.asset_type_boxback:
                        game_metadata_key = config.metadata_key_boxback
                    elif asset_type == config.asset_type_boxfront:
                        game_metadata_key = config.metadata_key_boxfront
                    elif asset_type == config.asset_type_label:
                        game_metadata_key = config.metadata_key_label
                    elif asset_type == config.asset_type_screenshot:
                        game_metadata_key = config.metadata_key_screenshot
                    elif asset_type == config.asset_type_video:
                        game_metadata_key = config.metadata_key_video

                    # If one of the minimum asset types, make sure it's there
                    if asset_type in config.asset_types_min:
                        game_entry.set_value(game_metadata_key, game_asset_string)
                        continue

                    # Otherwise, only set if the file is present
                    if os.path.isfile(game_asset_file):
                        game_entry.set_value(game_metadata_key, game_asset_string)
                    else:
                        if game_entry.is_key_set(game_metadata_key):
                            game_entry.delete_value(game_metadata_key)
                self.set_game(game_platform, game_name, game_entry)

    # Download missing videos
    def download_missing_videos(self, search_terms = "", num_results = 10, verbose = False, exit_on_failure = False):
        for metadata_entry in self.get_all_sorted_entries():
            if not metadata_entry.is_key_set(config.metadata_key_video):

                # Get game details
                game_name = metadata_entry.get_game()
                game_regular_name = gameinfo.DeriveRegularNameFromGameName(game_name)
                game_platform = metadata_entry.get_platform()
                game_category = metadata_entry.get_category()
                game_subcategory = metadata_entry.get_subcategory()

                # Get expected video file
                expected_video_file = environment.GetLockerGamingAssetFile(game_category, game_subcategory, game_name, config.asset_type_video)
                if os.path.exists(expected_video_file):
                    continue

                # Get search results
                search_results = youtube.GetSearchResults(
                    search_terms = search_terms + "+" + game_regular_name,
                    num_results = num_results,
                    sort_by_duration = True,
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)
                if len(search_results) == 0:
                    continue

                # Show search results to the user
                system.Log("Here are the search results for \"%s\"" % game_name)
                for index in range(0, len(search_results)):
                    search_result = search_results[index]
                    system.Log("%d) \"%s\" (%s) [%s] - %s" % (index, search_result["title"], search_result["channel"], search_result["duration_string"], search_result["url"]))

                # Ask them which one they want to use
                value = system.PromptForValue("Which do you want to use? [Leave empty to skip, type quit to stop]")
                if not value:
                    continue
                if value.lower() == "quit":
                    break

                # Get selected search result
                selected_search_result = None
                try:
                    selected_search_result = search_results[int(value)]
                except:
                    continue
                if not selected_search_result:
                    continue

                # Download selected result
                success = youtube.DownloadVideo(
                    video_url = selected_search_result["url"],
                    output_file = expected_video_file,
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)
                if not success:
                    continue

                # Clean exif data
                if os.path.exists(expected_video_file):
                    asset.CleanExifData(
                        asset_file = expected_video_file,
                        verbose = verbose,
                        exit_on_failure = exit_on_failure)

    # Scan rom base directory
    def scan_rom_base_dir(self, rom_base_dir, rom_category, rom_subcategory, verbose = False, exit_on_failure = False):
        for obj in system.GetDirectoryContents(rom_base_dir):
            rom_dir = os.path.join(rom_base_dir, obj)

            # Skip non-game folders
            if not rom_dir.endswith(")"):
                continue

            # Get info
            rom_name = system.GetDirectoryName(rom_dir)
            rom_platform = gameinfo.DeriveGamePlatformFromCategories(rom_category, rom_subcategory)

            # Get file
            rom_file = system.RebaseFilePath(
                path = environment.GetJsonRomMetadataFile(rom_category, rom_subcategory, rom_name),
                old_base_path = environment.GetJsonRomsMetadataRootDir(),
                new_base_path = "")

            # Get asset files
            rom_boxfront = gameinfo.DeriveGameAssetPathFromName(rom_name, config.asset_type_boxfront)
            rom_boxback = gameinfo.DeriveGameAssetPathFromName(rom_name, config.asset_type_boxback)
            rom_background = gameinfo.DeriveGameAssetPathFromName(rom_name, config.asset_type_background)
            rom_screenshot = gameinfo.DeriveGameAssetPathFromName(rom_name, config.asset_type_screenshot)
            rom_video = gameinfo.DeriveGameAssetPathFromName(rom_name, config.asset_type_video)

            # Create new entry
            if verbose:
                system.Log("Found game: '%s' - '%s'" % (rom_platform, rom_name))
            game_entry = MetadataEntry()
            game_entry.set_platform(rom_platform)
            game_entry.set_game(rom_name)
            game_entry.set_file(rom_file)
            game_entry.set_boxfront(rom_boxfront)
            game_entry.set_boxback(rom_boxback)
            game_entry.set_background(rom_background)
            game_entry.set_screenshot(rom_screenshot)
            game_entry.set_players("1")
            game_entry.set_coop("No")
            game_entry.set_playable("Yes")
            self.add_game(game_entry)

    # Scan roms
    def scan_roms(self, rom_path, rom_category, rom_subcategory, verbose = False, exit_on_failure = False):
        if rom_category == config.game_category_computer:
            for obj in system.GetDirectoryContents(rom_path):
                self.scan_rom_base_dir(
                    rom_base_dir = os.path.join(rom_path, obj),
                    rom_category = rom_category,
                    rom_subcategory = rom_subcategory,
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)
        else:
            self.scan_rom_base_dir(
                rom_base_dir = rom_path,
                rom_category = rom_category,
                rom_subcategory = rom_subcategory,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

    # Import from pegasus file
    def import_from_pegasus_file(
        self,
        pegasus_file,
        verbose = False,
        exit_on_failure = False):
        if os.path.exists(pegasus_file):
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
                    game_entry = MetadataEntry()
                    game_entry.set_platform(collection_platform)
                    in_description_section = False

                    # Parse entry tokens
                    for line in token.split("\n"):

                        # Game
                        if line.startswith("game:"):
                            in_description_section = False
                            game_entry.set_game(line.replace("game:", "").strip())

                        # File
                        elif line.startswith("file:"):
                            in_description_section = False
                            game_entry.set_file(line.replace("file:", "").strip())

                        # Developer
                        elif line.startswith("developer:"):
                            in_description_section = False
                            game_entry.set_developer(line.replace("developer:", "").strip())

                        # Publisher
                        elif line.startswith("publisher:"):
                            in_description_section = False
                            game_entry.set_publisher(line.replace("publisher:", "").strip())

                        # Genre
                        elif line.startswith("genre:"):
                            in_description_section = False
                            game_entry.set_genre(line.replace("genre:", "").strip())

                        # Tag
                        elif line.startswith("tag:"):
                            in_description_section = False
                            game_entry.set_tag(line.replace("tag:", "").strip())

                        # Description
                        elif line.startswith("description:"):
                            in_description_section = True
                            game_entry.set_description([])
                        elif line.startswith("  ") and in_description_section:
                            description_lines = game_entry.get_description()
                            description_lines.append(line.strip())
                            game_entry.set_description(description_lines)

                        # Release
                        elif line.startswith("release:"):
                            in_description_section = False
                            game_entry.set_release(line.replace("release:", "").strip())

                        # Players
                        elif line.startswith("players:"):
                            in_description_section = False
                            game_entry.set_players(line.replace("players:", "").strip())

                        # Boxfront
                        elif line.startswith("assets.boxfront:"):
                            in_description_section = False
                            game_entry.set_boxfront(line.replace("assets.boxfront:", "").strip())

                        # Boxback
                        elif line.startswith("assets.boxback:"):
                            in_description_section = False
                            game_entry.set_boxback(line.replace("assets.boxback:", "").strip())

                        # Background
                        elif line.startswith("assets.background:"):
                            in_description_section = False
                            game_entry.set_background(line.replace("assets.background:", "").strip())

                        # Screenshot
                        elif line.startswith("assets.screenshot:"):
                            in_description_section = False
                            game_entry.set_screenshot(line.replace("assets.screenshot:", "").strip())

                        # Video
                        elif line.startswith("assets.video:"):
                            in_description_section = False
                            game_entry.set_video(line.replace("assets.video:", "").strip())

                        # Co-op
                        elif line.startswith("x-co-op:"):
                            in_description_section = False
                            game_entry.set_coop(line.replace("x-co-op:", "").strip())

                        # Playable
                        elif line.startswith("x-playable:"):
                            in_description_section = False
                            game_entry.set_playable(line.replace("x-playable:", "").strip())

                    # Add new entry
                    if game_entry.has_minimum_keys():
                        self.add_game(game_entry)

    # Import from metadata file
    def import_from_metadata_file(
        self,
        metadata_file,
        metadata_format = config.metadata_format_type_pegasus,
        verbose = False,
        exit_on_failure = False):
        if metadata_format == config.metadata_format_type_pegasus:
            self.import_from_pegasus_file(
                pegasus_file = metadata_file,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

    # Export to pegasus file
    def export_to_pegasus_file(
        self,
        pegasus_file,
        append_existing = False,
        verbose = False,
        exit_on_failure = False):
        file_mode = "a" if append_existing else "w"
        if not os.path.exists(pegasus_file):
            system.TouchFile(
                src = pegasus_file,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
        with open(pegasus_file, file_mode, encoding="utf8", newline="\n") as file:
            for game_platform in self.get_sorted_platforms():
                game_supercategory, game_category, game_subcategory = gameinfo.DeriveGameCategoriesFromPlatform(game_platform)

                # Write header
                file.write("collection: %s\n" % game_platform)
                file.write("launch: {env.JOYBOX_LAUNCH_JSON} -c \"%s\" -s \"%s\" -n {file.basename}\n" % (game_category, game_subcategory))
                file.write("\n\n")

                # Write each entry
                for game_entry in self.get_sorted_entries(game_platform):

                    # Game
                    if game_entry.is_key_set(config.metadata_key_game):
                        file.write("game: " + game_entry.get_game() + "\n")

                    # File
                    if game_entry.is_key_set(config.metadata_key_file):
                        file.write("file: " + game_entry.get_file() + "\n")

                    # Developer
                    if game_entry.is_key_set(config.metadata_key_developer):
                        file.write("developer: " + game_entry.get_developer() + "\n")

                    # Publisher
                    if game_entry.is_key_set(config.metadata_key_publisher):
                        file.write("publisher: " + game_entry.get_publisher() + "\n")

                    # Genre
                    if game_entry.is_key_set(config.metadata_key_genre):
                        file.write("genre: " + game_entry.get_genre() + "\n")

                    # Description
                    if game_entry.is_key_set(config.metadata_key_description):
                        file.write("description:\n")
                        for desc_line in game_entry.get_description():
                            file.write("  " + desc_line + "\n")

                    # Release
                    if game_entry.is_key_set(config.metadata_key_release):
                        file.write("release: " + game_entry.get_release() + "\n")

                    # Players
                    if game_entry.is_key_set(config.metadata_key_players):
                        file.write("players: " + game_entry.get_players() + "\n")

                    # Boxfront
                    if game_entry.is_key_set(config.metadata_key_boxfront):
                        file.write("assets.boxfront: " + game_entry.get_boxfront() + "\n")

                    # Boxback
                    if game_entry.is_key_set(config.metadata_key_boxback):
                        file.write("assets.boxback: " + game_entry.get_boxback() + "\n")

                    # Background
                    if game_entry.is_key_set(config.metadata_key_background):
                        file.write("assets.background: " + game_entry.get_background() + "\n")

                    # Screenshot
                    if game_entry.is_key_set(config.metadata_key_screenshot):
                        file.write("assets.screenshot: " + game_entry.get_screenshot() + "\n")

                    # Video
                    if game_entry.is_key_set(config.metadata_key_video):
                        file.write("assets.video: " + game_entry.get_video() + "\n")

                    # Co-op
                    if game_entry.is_key_set(config.metadata_key_coop):
                        file.write("x-co-op: " + game_entry.get_coop() + "\n")

                    # Playable
                    if game_entry.is_key_set(config.metadata_key_playable):
                        file.write("x-playable: " + game_entry.get_playable() + "\n")

                    # Divider
                    file.write("\n\n")

    # Export to metadata file
    def export_to_metadata_file(
        self,
        metadata_file,
        metadata_format = config.metadata_format_type_pegasus,
        append_existing = False,
        verbose = False,
        exit_on_failure = False):
        if metadata_format == config.metadata_format_type_pegasus:
            self.export_to_pegasus_file(
                pegasus_file = metadata_file,
                append_existing = append_existing,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

# Collect metadata
def CollectMetadata(
    metadata_dir,
    metadata_source,
    keys_to_check = [],
    force_download = False,
    allow_replacing = False,
    select_automatically = False,
    ignore_unowned = False,
    verbose = False,
    exit_on_failure = False):

    # Find missing metadata
    metadata_dir = os.path.realpath(metadata_dir)
    for file in system.BuildFileList(metadata_dir):
        if environment.IsMetadataFile(file):
            metadata_obj = Metadata()
            metadata_obj.import_from_metadata_file(file)

            # Get keys to check
            metadata_keys_to_check = []
            if isinstance(keys_to_check, list) and len(keys_to_check) > 0:
                metadata_keys_to_check = keys_to_check
            else:
                metadata_keys_to_check = config.metadata_keys_downloadable

            # Iterate through each game entry to fill in any missing data
            for game_platform in metadata_obj.get_sorted_platforms():
                for game_name in metadata_obj.get_sorted_names(game_platform):
                    if not force_download:
                        if not metadata_obj.is_entry_missing_data(game_platform, game_name, metadata_keys_to_check):
                            continue

                    # Get entry
                    if verbose:
                        system.Log("Collecting metadata for %s - %s ..." % (game_platform, game_name))
                    game_entry = metadata_obj.get_game(game_platform, game_name)

                    # Create web driver
                    web_driver = webpage.CreateWebDriver()

                    # Collect metadata
                    metadata_result = None
                    if metadata_source == config.metadata_source_type_thegamesdb:
                        metadata_result = CollectMetadataFromTGDB(
                            web_driver = web_driver,
                            game_platform = game_platform,
                            game_name = game_name,
                            select_automatically = select_automatically,
                            ignore_unowned = ignore_unowned,
                            verbose = verbose,
                            exit_on_failure = exit_on_failure)
                    elif metadata_source == config.metadata_source_type_gamefaqs:
                        metadata_result = CollectMetadataFromGameFAQS(
                            web_driver = web_driver,
                            game_platform = game_platform,
                            game_name = game_name,
                            select_automatically = select_automatically,
                            ignore_unowned = ignore_unowned,
                            verbose = verbose,
                            exit_on_failure = exit_on_failure)
                    elif metadata_source == config.metadata_source_type_itchio:
                        metadata_result = CollectMetadataFromItchio(
                            web_driver = web_driver,
                            game_platform = game_platform,
                            game_name = game_name,
                            select_automatically = select_automatically,
                            ignore_unowned = ignore_unowned,
                            verbose = verbose,
                            exit_on_failure = exit_on_failure)

                    # Cleanup web driver
                    webpage.DestroyWebDriver(web_driver)

                    # Merge in metadata result
                    if metadata_result:

                        # Update keys
                        for metadata_key in metadata_keys_to_check:
                            if not metadata_result.is_key_set(metadata_key):
                                continue
                            if game_entry.is_key_set(metadata_key) and not allow_replacing:
                                continue
                            game_entry.set_value(metadata_key, metadata_result.get_value(metadata_key))

                    # Write metadata back to file
                    metadata_obj.set_game(game_platform, game_name, game_entry)
                    metadata_obj.export_to_metadata_file(file)

                    # Wait
                    if verbose:
                        system.Log("Waiting to get next entry ...")
                    time.sleep(5)

# Collect metadata from TheGamesDB
def CollectMetadataFromTGDB(
    web_driver,
    game_platform,
    game_name,
    select_automatically = False,
    ignore_unowned = False,
    verbose = False,
    exit_on_failure = False):

    # Get keywords name
    natural_name = gameinfo.DeriveRegularNameFromGameName(game_name)
    keywords_name = urllib.parse.quote_plus(natural_name.strip())

    # Metadata result
    metadata_result = MetadataEntry()

    # Go to the search page and pull the results
    try:
        web_driver.get("https://thegamesdb.net/search.php?name=" + keywords_name)
    except:
        return None

    # Select an entry automatically
    if select_automatically:

        # Find the root container element
        section_search_result = webpage.WaitForPageElement(web_driver, class_name = "container-fluid", wait_time = 5, verbose = verbose)
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
                score_entry = {}
                score_entry["node"] = game_card
                score_entry["ratio"] = system.GetStringSimilarityRatio(natural_name, potential_title)
                scores_list.append(score_entry)

        # Click on the highest score node
        for score_entry in sorted(scores_list, key=lambda d: d["ratio"], reverse=True):
            webpage.ClickElement(score_entry["node"])
            break

        # Check if the url has changed
        if webpage.IsUrlLoaded(web_driver, "https://thegamesdb.net/search.php?name="):
            return None

    # Look for game description
    section_game_description = webpage.WaitForPageElement(web_driver, class_name = "game-overview", verbose = verbose)
    if not section_game_description:
        return None

    # Grab the description text
    raw_game_description = webpage.GetElementText(section_game_description)

    # Convert description to metadata format
    if raw_game_description:
        metadata_result.set_description(CleanRawGameDescription(raw_game_description))

    # Look for game details
    for section_game_details in webpage.GetElement(web_driver, class_name = "card-body", all_elements = True):
        for element_paragraph in webpage.GetElement(section_game_details, tag_name = "p", all_elements = True):
            element_text = webpage.GetElementText(element_paragraph)
            if not element_text:
                continue

            # Genre
            if "Genre(s):" in element_text:
                metadata_result.set_genre(element_text.replace("Genre(s):", "").replace(" | ", ";").strip())

            # Co-op
            if "Co-op:" in element_text:
                metadata_result.set_coop(element_text.replace("Co-op:", "").strip())

            # Developer
            if "Developer(s):" in element_text:
                metadata_result.set_developer(element_text.replace("Developer(s):", "").strip())

            # Publisher
            if "Publishers(s):" in element_text:
                metadata_result.set_publisher(element_text.replace("Publishers(s):", "").strip())

            # Players
            if "Players:" in element_text:
                metadata_result.set_players(element_text.replace("Players:", "").strip())

            # Release
            if "ReleaseDate:" in element_text:
                metadata_result.set_release(element_text.replace("ReleaseDate:", "").strip())

    # Return metadata
    return metadata_result

# Collect metadata from GameFAQs
def CollectMetadataFromGameFAQS(
    web_driver,
    game_platform,
    game_name,
    select_automatically = False,
    ignore_unowned = False,
    verbose = False,
    exit_on_failure = False):

    # Get keywords name
    natural_name = gameinfo.DeriveRegularNameFromGameName(game_name)
    keywords_name = urllib.parse.quote_plus(natural_name.strip())

    # Metadata result
    metadata_result = MetadataEntry()

    # Go to the search page and pull the results
    try:
        web_driver.get("https://gamefaqs.gamespot.com/search_advanced?game=" + keywords_name)
    except:
        return None

    # Look for game description
    section_game_descriptions = webpage.WaitForPageElement(web_driver, class_name = "game_desc", verbose = verbose)
    if not section_game_descriptions:
        return None

    # Grab the description text
    raw_game_description = ""
    for section_game_description in section_game_descriptions:
        raw_game_description = webpage.GetElementText(section_game_description)

    # Click the "more" button if it's present
    if "more »" in raw_game_description:
        element_game_description_more = webpage.GetElement(web_driver, link_text = "more »")
        if element_game_description_more:
            webpage.ClickElement(element_game_description_more)

    # Re-grab the description text
    for section_game_description in section_game_descriptions:
        raw_game_description = webpage.GetElementText(section_game_description)

    # Convert description to metadata format
    if raw_game_description:
        metadata_result.set_description(CleanRawGameDescription(raw_game_description))

    # Look for game details
    for section_game_details in webpage.GetElement(web_driver, class_name = "content", all_elements = True):
        element_text = webpage.GetElementText(section_game_details)
        if not element_text:
            continue

        # Genre
        if element_text.startswith("Genre:"):
            metadata_result.set_genre(element_text.replace("Genre:", "").replace(" » ", ";").strip())

        # Developer
        elif element_text.startswith("Developer:"):
            metadata_result.set_developer(element_text.replace("Developer:", "").strip())

        # Publisher
        elif element_text.startswith("Publisher:"):
            metadata_result.set_publisher(element_text.replace("Publisher:", "").strip())

        # Developer/Publisher
        elif element_text.startswith("Developer/Publisher:"):
            metadata_result.set_developer(element_text.replace("Developer/Publisher:", "").strip())
            metadata_result.set_publisher(element_text.replace("Developer/Publisher:", "").strip())

        # Release/First Released
        elif element_text.startswith("Release:") or element_text.startswith("First Released:"):
            import dateutil.parser
            release_text = ""
            if element_text.startswith("Release:"):
                release_text = element_text.replace("Release:", "").strip()
            elif element_text.startswith("First Released:"):
                release_text = element_text.replace("First Released:", "").strip()
            release_time = dateutil.parser.parse(release_text)
            metadata_result.set_release(release_time.strftime("%Y-%m-%d"))

    # Return metadata
    return metadata_result

# Collect metadata from Itch.io
def CollectMetadataFromItchio(
    web_driver,
    game_platform,
    game_name,
    select_automatically = False,
    ignore_unowned = False,
    verbose = False,
    exit_on_failure = False):

    # Get keywords name
    natural_name = gameinfo.DeriveRegularNameFromGameName(game_name)
    keywords_name = urllib.parse.quote_plus(natural_name.strip())

    # Metadata result
    metadata_result = MetadataEntry()

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
        section_my_feed = webpage.WaitForPageElement(web_driver, link_text = "My feed", verbose = verbose)
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
        section_search_result = webpage.WaitForPageElement(web_driver, class_name = "game_cell", verbose = verbose)
        if section_search_result:
            webpage.ClickElement(section_search_result)
        while webpage.GetCurrentPageUrl(web_driver).startswith("https://itch.io/search?q="):
            time.sleep(1)

    # Ignore unowned games
    if ignore_unowned:
        section_game_purchased = webpage.WaitForPageElement(web_driver, class_name = "purchase_banner_inner", wait_time = 3, verbose = verbose)
        if not section_game_purchased:
            return None

    # Look for game description
    section_game_description = webpage.WaitForPageElement(web_driver, class_name = "formatted_description", verbose = verbose)
    if not section_game_description:
        return None

    # Look for game information
    section_game_information = webpage.WaitForPageElement(web_driver, class_name = "more_information_toggle", verbose = verbose)
    if not section_game_information:
        return None

    # Grab the description text
    raw_game_description = webpage.GetElementText(section_game_description)

    # Convert description to metadata format
    if raw_game_description:
        metadata_result.set_description(CleanRawGameDescription(raw_game_description))

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
                metadata_result.set_release(release_time.strftime("%Y-%m-%d"))
            if game_detail_line.startswith("Published"):
                release_text = game_detail_line.replace("Published", "").strip()
                release_time = datetime.datetime.strptime(release_text, "%b %d, %Y")
                metadata_result.set_release(release_time.strftime("%Y-%m-%d"))

            # Developer/publisher
            elif game_detail_line.startswith("Authors"):
                author_text = game_detail_line.replace("Authors", "").strip()
                metadata_result.set_developer(author_text)
                metadata_result.set_publisher(author_text)
            elif game_detail_line.startswith("Author"):
                author_text = game_detail_line.replace("Author", "").strip()
                metadata_result.set_developer(author_text)
                metadata_result.set_publisher(author_text)

            # Genre
            elif game_detail_line.startswith("Genre"):
                metadata_result.set_genre(game_detail_line.replace("Genre", "").strip().replace(", ", ";"))

    # Return metadata
    return metadata_result

# Clean raw game description
def CleanRawGameDescription(raw_description):

    # Clean rich text
    new_description = system.CleanRichTextString(raw_description)

    # Replace leftover html
    new_description = new_description.replace("<span>", " ")
    new_description = new_description.replace("</span>", " ")
    new_description = new_description.replace("&lt;", " ")
    new_description = new_description.replace("&gt;", " ")
    new_description = new_description.replace("&quot;", " ")
    new_description = new_description.replace("&amp;", " ")
    new_description = new_description.replace("amp;", " ")

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
