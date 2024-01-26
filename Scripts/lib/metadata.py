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

# General metadata class
class Metadata:

    # Constructor
    def __init__(self):
        self.game_database = {}

    # Add game entry
    def add_game(self, game_entry):

        # Check minimum keys
        for key in config.metadata_keys_minimum:
            if not key in game_entry:
                return

        # Get game info
        game_platform = game_entry[config.metadata_key_platform]
        game_name = game_entry[config.metadata_key_game]

        # Inject categories
        game_supercategory, game_category, game_subcategory = gameinfo.DeriveGameCategoriesFromPlatform(game_platform)
        game_entry[config.metadata_key_supercategory] = game_supercategory
        game_entry[config.metadata_key_category] = game_category
        game_entry[config.metadata_key_subcategory] = game_subcategory

        # Add platform if not already there
        if not game_platform in self.game_database.keys():
            self.game_database[game_platform] = {}

        # Add entry
        import mergedeep
        if game_name in self.game_database[game_platform]:
            self.game_database[game_platform][game_name] = mergedeep.merge(game_entry, self.game_database[game_platform][game_name])
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
                file_path_relative = game_entry[config.metadata_key_file]
                file_path_real = os.path.join(environment.GetJsonRomsMetadataRootDir(), file_path_relative)
                if not os.path.exists(file_path_real):
                    print("File not found:\n%s" % file_path_relative)
                    print("Verification of game %s in platform %s failed" % (game_name, game_platform))
                    sys.exit(1)

    # Sync assets
    def sync_assets(self):
        for game_platform in self.get_sorted_platforms():
            for game_name in self.get_sorted_names(game_platform):
                game_entry = self.get_game(game_platform, game_name)
                game_supercategory, game_category, game_subcategory = gameinfo.DeriveGameCategoriesFromPlatform(game_platform)
                for asset_type in config.asset_types_all:
                    game_asset_string = "%s/%s%s" % (asset_type, game_name, config.asset_type_extensions[asset_type])
                    game_asset_file = environment.GetSyncedGameAssetFile(game_category, game_subcategory, game_name, asset_type)
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
                    if asset_type in config.asset_types_min:
                        game_entry[game_metadata_key] = game_asset_string
                        continue
                    if os.path.isfile(game_asset_file):
                        game_entry[game_metadata_key] = game_asset_string
                    else:
                        if game_metadata_key in game_entry:
                            del game_entry[game_metadata_key]
                self.set_game(game_platform, game_name, game_entry)

    # Scan rom base directory
    def scan_rom_base_dir(self, rom_base_dir, rom_category, rom_subcategory):
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
            rom_boxfront = "%s/%s%s" % (config.asset_type_boxfront, rom_name, config.asset_type_extensions[config.asset_type_boxfront])
            rom_boxback = "%s/%s%s" % (config.asset_type_boxback, rom_name, config.asset_type_extensions[config.asset_type_boxback])
            rom_background = "%s/%s%s" % (config.asset_type_background, rom_name, config.asset_type_extensions[config.asset_type_background])
            rom_screenshot = "%s/%s%s" % (config.asset_type_screenshot, rom_name, config.asset_type_extensions[config.asset_type_screenshot])
            rom_video = "%s/%s%s" % (config.asset_type_video, rom_name, config.asset_type_extensions[config.asset_type_video])

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
            game_entry[config.metadata_key_players] = "1"
            game_entry[config.metadata_key_coop] = "No"
            game_entry[config.metadata_key_playable] = "Yes"
            self.add_game(game_entry)

    # Scan roms
    def scan_roms(self, rom_path, rom_category, rom_subcategory):
        if rom_category == config.game_category_computer:
            for obj in system.GetDirectoryContents(rom_path):
                self.scan_rom_base_dir(os.path.join(rom_path, obj), rom_category, rom_subcategory)
        else:
            self.scan_rom_base_dir(rom_path, rom_category, rom_subcategory)

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

                    # Playable
                    elif line.startswith("x-playable:"):
                        in_description_section = False
                        game_entry[config.metadata_key_playable] = line.replace("x-playable:", "").strip()

                # Check minimum keys
                has_minimum_keys = True
                for key in config.metadata_keys_minimum:
                    if not key in game_entry:
                        has_minimum_keys = False

                # Add new entry
                if has_minimum_keys:
                    self.add_game(game_entry)

    # Import from metadata file
    def import_from_metadata_file(self, metadata_file, metadata_format = config.metadata_format_type_pegasus):
        if metadata_format == config.metadata_format_type_pegasus:
            self.import_from_pegasus_file(metadata_file)

    # Export to pegasus file
    def export_to_pegasus_file(self, pegasus_file, append_existing = False):
        file_mode = "a" if append_existing else "w"
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

                    # Playable
                    if config.metadata_key_playable in game_entry:
                        file.write("x-playable: " + game_entry[config.metadata_key_playable] + "\n")

                    # Divider
                    file.write("\n\n")

    # Export to metadata file
    def export_to_metadata_file(self, metadata_file, metadata_format = config.metadata_format_type_pegasus, append_existing = False):
        if metadata_format == config.metadata_format_type_pegasus:
            self.export_to_pegasus_file(metadata_file, append_existing)

# Collect metadata
def CollectMetadata(
    metadata_dir,
    metadata_source,
    only_check_description = False,
    only_check_genre = False,
    only_check_developer = False,
    only_check_publisher = False,
    only_check_release = False,
    force_download = False,
    select_automatically = False,
    ignore_unowned = False):

    # Create web driver
    web_driver = webpage.CreateWebDriver()

    # Find missing metadata
    metadata_dir = os.path.realpath(metadata_dir)
    for file in system.BuildFileList(metadata_dir):
        if environment.IsMetadataFile(file):
            metadata_obj = Metadata()
            metadata_obj.import_from_metadata_file(file)

            # Check for missing metadata keys
            metadata_keys_to_check = []
            is_missing_metadata = False
            if force_download:
                is_missing_metadata = True
            else:
                if only_check_description:
                    metadata_keys_to_check = [config.metadata_key_description]
                elif only_check_genre:
                    metadata_keys_to_check = [config.metadata_key_genre]
                elif only_check_developer:
                    metadata_keys_to_check = [config.metadata_key_developer]
                elif only_check_publisher:
                    metadata_keys_to_check = [config.metadata_key_publisher]
                elif only_check_release:
                    metadata_keys_to_check = [config.metadata_key_release]
                else:
                    metadata_keys_to_check = config.metadata_keys_missing
                is_missing_metadata = metadata_obj.is_missing_data(metadata_keys_to_check)
            if not is_missing_metadata:
                continue

            # Iterate through each game entry to fill in any missing data
            for game_platform in metadata_obj.get_sorted_platforms():
                for game_name in metadata_obj.get_sorted_names(game_platform):
                    if not force_download:
                        if not metadata_obj.is_entry_missing_data(game_platform, game_name, metadata_keys_to_check):
                            continue

                    # Get entry
                    game_entry = metadata_obj.get_game(game_platform, game_name)

                    # Collect metadata
                    metadata_result = None
                    if metadata_source == config.metadata_source_type_thegamesdb:
                        metadata_result = CollectMetadataFromTGDB(
                            web_driver = web_driver,
                            game_platform = game_platform,
                            game_name = game_name,
                            select_automatically = select_automatically,
                            ignore_unowned = ignore_unowned)
                    elif metadata_source == config.metadata_source_type_gamefaqs:
                        metadata_result = CollectMetadataFromGameFAQS(
                            web_driver = web_driver,
                            game_platform = game_platform,
                            game_name = game_name,
                            select_automatically = select_automatically,
                            ignore_unowned = ignore_unowned)
                    elif metadata_source == config.metadata_source_type_itchio:
                        metadata_result = CollectMetadataFromItchio(
                            web_driver = web_driver,
                            game_platform = game_platform,
                            game_name = game_name,
                            select_automatically = select_automatically,
                            ignore_unowned = ignore_unowned)

                    # Set metadata that was not already present in the file
                    if metadata_result:
                        for metadata_key in config.metadata_keys_replaceable:

                            # Ignore keys not in result
                            if not metadata_key in metadata_result.keys():
                                continue

                            # Check if we should set the new data
                            should_set_data = False
                            if metadata_key == config.metadata_key_players:
                                should_set_data = True
                            if metadata_key == config.metadata_key_coop:
                                should_set_data = True
                            elif not metadata_key in game_entry.keys():
                                should_set_data = True

                            # Set new data
                            if should_set_data:
                                game_entry[metadata_key] = metadata_result[metadata_key]

                    # Write metadata back to file
                    metadata_obj.set_game(game_platform, game_name, game_entry)
                    metadata_obj.export_to_metadata_file(file)

    # Cleanup web driver
    webpage.DestroyWebDriver(web_driver)

# Collect metadata from TheGamesDB
def CollectMetadataFromTGDB(web_driver, game_platform, game_name, select_automatically = False, ignore_unowned = False):

    # Get keywords name
    natural_name = gameinfo.DeriveRegularNameFromGameName(game_name)
    keywords_name = urllib.parse.quote_plus(natural_name.strip())

    # Metadata result
    metadata_result = {}

    # Go to the search page and pull the results
    try:
        web_driver.get("https://thegamesdb.net/search.php?name=" + keywords_name)
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
        metadata_result[config.metadata_key_description] = CleanRawGameDescription(raw_game_description)

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
    natural_name = gameinfo.DeriveRegularNameFromGameName(game_name)
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
        metadata_result[config.metadata_key_description] = CleanRawGameDescription(raw_game_description)

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
    natural_name = gameinfo.DeriveRegularNameFromGameName(game_name)
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
        metadata_result[config.metadata_key_description] = CleanRawGameDescription(raw_game_description)

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

# Clean raw game description
def CleanRawGameDescription(raw_description):

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
