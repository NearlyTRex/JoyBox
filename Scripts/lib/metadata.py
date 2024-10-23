# Imports
import os, os.path
import sys
import random

# Local imports
import config
import system
import environment
import platforms
import gameinfo
import youtube
import asset
import metadataentry

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

        # Add entry
        self.set_game(game_platform, game_name, game_entry)

    # Get game entry
    def get_game(self, game_platform, game_name):
        if game_platform in self.game_database:
            if game_name in self.game_database[game_platform]:
                return self.game_database[game_platform][game_name]
        return None

    # Set game entry
    def set_game(self, game_platform, game_name, game_entry):
        if not game_platform in self.game_database.keys():
            self.game_database[game_platform] = {}
        if game_name in self.game_database[game_platform]:
            self.game_database[game_platform][game_name].merge(game_entry)
        else:
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
            merge_type = config.merge_type_replace
        self.game_database = system.MergeDictionaries(
            dict1 = self.game_database,
            dict2 = other.game_database,
            merge_type = merge_type)

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
            game_entry = metadataentry.MetadataEntry()
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
                    game_entry = metadataentry.MetadataEntry()
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

                        # Url
                        elif line.startswith("x-url:"):
                            in_description_section = False
                            game_entry.set_url(line.replace("x-url:", "").strip())

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

                    # Url
                    if game_entry.is_key_set(config.metadata_key_url):
                        file.write("x-url: " + game_entry.get_url() + "\n")

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
