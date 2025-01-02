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
            merge_type = config.MergeType.REPLACE
        self.game_database = system.MergeDictionaries(
            dict1 = self.game_database,
            dict2 = other.game_database,
            merge_type = merge_type)

    # Sync assets in each entry
    def sync_assets(self):
        for entry in self.get_all_sorted_entries():
            entry.sync_assets()

    # Verify files
    def verify_files(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        for game_platform in self.get_sorted_platforms():
            for game_name in self.get_sorted_names(game_platform):
                if verbose:
                    system.LogInfo("Checking '%s - %s' ..." % (game_platform, game_name))

                # Get game entry
                game_entry = self.get_game(game_platform, game_name)

                # Check file paths
                file_path_relative = game_entry.get_file()
                file_path_real = os.path.join(environment.GetJsonRomsMetadataRootDir(), file_path_relative)
                if not os.path.exists(file_path_real):
                    system.LogError("File not found:\n%s" % file_path_relative)
                    system.LogErrorAndQuit("Verification of '%s - %s' failed" % (game_platform, game_name))

    # Import from pegasus file
    def import_from_pegasus_file(
        self,
        pegasus_file,
        verbose = False,
        pretend_run = False,
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
                    game_entry.set_platform(config.Platform.from_string(collection_platform))
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
        metadata_format = config.MetadataFormatType.PEGASUS,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        if metadata_format == config.MetadataFormatType.PEGASUS:
            self.import_from_pegasus_file(
                pegasus_file = metadata_file,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

    # Export to pegasus file
    def export_to_pegasus_file(
        self,
        pegasus_file,
        append_existing = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        file_mode = "a" if append_existing else "w"
        if not os.path.exists(pegasus_file):
            system.TouchFile(
                src = pegasus_file,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        with open(pegasus_file, file_mode, encoding="utf8", newline="\n") as file:
            for game_platform in self.get_sorted_platforms():
                game_supercategory, game_category, game_subcategory = gameinfo.DeriveGameCategoriesFromPlatform(game_platform)

                # Get launch command
                launch_cmd = [
                    "{env.JOYBOX_LAUNCH_JSON}",
                    "-c", "\"" + game_category.val() + "\"",
                    "-s", "\"" + game_subcategory.val() + "\"",
                    "-n", "{file.basename}"
                ]

                # Write header
                file.write("collection: %s\n" % game_platform.val())
                file.write("launch: %s\n" % " ".join(launch_cmd))
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
