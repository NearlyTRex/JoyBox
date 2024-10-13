# Imports
import os, os.path
import sys

# Local imports
import config
import system

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
        if self.is_key_set(key):
            return self.game_entry[key]
        return None

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

    # Game url
    def get_url(self):
        return self.get_value(config.metadata_key_url)
    def set_url(self, value):
        self.set_value(config.metadata_key_url, value)

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
