# Imports
import copy

# Local imports
from joybox import config
from joybox import datautils
from joybox import text
from joybox import environment
from joybox import gamenaming
from joybox import paths

# Metadata key holding each asset type's path
asset_metadata_keys = {
    config.AssetType.BACKGROUND: config.METADATA_KEY_BACKGROUND,
    config.AssetType.BOXBACK: config.METADATA_KEY_BOXBACK,
    config.AssetType.BOXFRONT: config.METADATA_KEY_BOXFRONT,
    config.AssetType.LABEL: config.METADATA_KEY_LABEL,
    config.AssetType.SCREENSHOT: config.METADATA_KEY_SCREENSHOT,
    config.AssetType.VIDEO: config.METADATA_KEY_VIDEO,
}

# Metadata entry class
class MetadataEntry:

    # Constructor
    def __init__(self):
        self.game_entry = {}

    # Has minimum keys
    def has_minimum_keys(self):
        for key in config.metadata_keys_minimum:
            if key not in self.game_entry.keys():
                return False
        return True

    # Determine if key is set
    def is_key_set(self, key):
        return key in self.game_entry.keys()

    # Get value
    def get_value(self, key, default_value = None):
        return self.game_entry.get(key, default_value)

    # Set value
    def set_value(self, key, value):
        self.game_entry[key] = value

    # Delete value
    def delete_value(self, key):
        del self.game_entry[key]

    # Merge data
    def merge(self, other, merge_type = None):
        if not merge_type:
            merge_type = config.MergeType.REPLACE
        self.game_entry = datautils.merge_dictionaries(
            dict1 = copy.deepcopy(other.game_entry),
            dict2 = self.game_entry,
            merge_type = merge_type)

    # Game name
    def get_game(self, default_value = None):
        return self.get_value(config.METADATA_KEY_GAME, default_value)
    def set_game(self, value):
        self.set_value(config.METADATA_KEY_GAME, value)

    # Game platform
    def get_platform(self, default_value = None):
        return self.get_value(config.METADATA_KEY_PLATFORM, default_value)
    def set_platform(self, value):
        self.set_value(config.METADATA_KEY_PLATFORM, value)

    # Game supercategory
    def get_supercategory(self, default_value = None):
        return self.get_value(config.METADATA_KEY_SUPERCATEGORY, default_value)
    def set_supercategory(self, value):
        self.set_value(config.METADATA_KEY_SUPERCATEGORY, value)

    # Game category
    def get_category(self, default_value = None):
        return self.get_value(config.METADATA_KEY_CATEGORY, default_value)
    def set_category(self, value):
        self.set_value(config.METADATA_KEY_CATEGORY, value)

    # Game subcategory
    def get_subcategory(self, default_value = None):
        return self.get_value(config.METADATA_KEY_SUBCATEGORY, default_value)
    def set_subcategory(self, value):
        self.set_value(config.METADATA_KEY_SUBCATEGORY, value)

    # Game file
    def get_file(self, default_value = None):
        return self.get_value(config.METADATA_KEY_FILE, default_value)
    def set_file(self, value):
        self.set_value(config.METADATA_KEY_FILE, value)

    # Game description
    def get_description(self, default_value = None):
        return self.get_value(config.METADATA_KEY_DESCRIPTION, default_value)
    def set_description(self, value):
        if isinstance(value, list):
            self.set_value(config.METADATA_KEY_DESCRIPTION, value)
        elif isinstance(value, str):
            cleaned_text = text.clean_web_text(value)
            lines = text.wrap_text_to_lines(cleaned_text)
            lines = datautils.deduplicate_adjacent_lines(lines)
            self.set_value(config.METADATA_KEY_DESCRIPTION, lines)

    # Game url
    def get_url(self, default_value = None):
        return self.get_value(config.METADATA_KEY_URL, default_value)
    def set_url(self, value):
        self.set_value(config.METADATA_KEY_URL, value)

    # Game genre
    def get_genre(self, default_value = None):
        return self.get_value(config.METADATA_KEY_GENRE, default_value)
    def set_genre(self, value):
        self.set_value(config.METADATA_KEY_GENRE, value)

    # Game coop
    def get_coop(self, default_value = None):
        return self.get_value(config.METADATA_KEY_COOP, default_value)
    def set_coop(self, value):
        self.set_value(config.METADATA_KEY_COOP, value)

    # Game playable
    def get_playable(self, default_value = None):
        return self.get_value(config.METADATA_KEY_PLAYABLE, default_value)
    def set_playable(self, value):
        self.set_value(config.METADATA_KEY_PLAYABLE, value)

    # Game developer
    def get_developer(self, default_value = None):
        return self.get_value(config.METADATA_KEY_DEVELOPER, default_value)
    def set_developer(self, value):
        self.set_value(config.METADATA_KEY_DEVELOPER, value)

    # Game publisher
    def get_publisher(self, default_value = None):
        return self.get_value(config.METADATA_KEY_PUBLISHER, default_value)
    def set_publisher(self, value):
        self.set_value(config.METADATA_KEY_PUBLISHER, value)

    # Game players
    def get_players(self, default_value = None):
        return self.get_value(config.METADATA_KEY_PLAYERS, default_value)
    def set_players(self, value):
        self.set_value(config.METADATA_KEY_PLAYERS, value)

    # Game release
    def get_release(self, default_value = None):
        return self.get_value(config.METADATA_KEY_RELEASE, default_value)
    def set_release(self, value):
        self.set_value(config.METADATA_KEY_RELEASE, value)

    # Game background
    def get_background(self, default_value = None):
        return self.get_value(config.METADATA_KEY_BACKGROUND, default_value)
    def set_background(self, value):
        self.set_value(config.METADATA_KEY_BACKGROUND, value)

    # Game box back
    def get_boxback(self, default_value = None):
        return self.get_value(config.METADATA_KEY_BOXBACK, default_value)
    def set_boxback(self, value):
        self.set_value(config.METADATA_KEY_BOXBACK, value)

    # Game box front
    def get_boxfront(self, default_value = None):
        return self.get_value(config.METADATA_KEY_BOXFRONT, default_value)
    def set_boxfront(self, value):
        self.set_value(config.METADATA_KEY_BOXFRONT, value)

    # Game label
    def get_label(self, default_value = None):
        return self.get_value(config.METADATA_KEY_LABEL, default_value)
    def set_label(self, value):
        self.set_value(config.METADATA_KEY_LABEL, value)

    # Game screenshot
    def get_screenshot(self, default_value = None):
        return self.get_value(config.METADATA_KEY_SCREENSHOT, default_value)
    def set_screenshot(self, value):
        self.set_value(config.METADATA_KEY_SCREENSHOT, value)

    # Game video
    def get_video(self, default_value = None):
        return self.get_value(config.METADATA_KEY_VIDEO, default_value)
    def set_video(self, value):
        self.set_value(config.METADATA_KEY_VIDEO, value)

    # Check if missing data
    def is_missing_data(self, keys_to_check):
        for key_to_check in keys_to_check:
            if not self.is_key_set(key_to_check):
                return True
            if self.is_key_set(key_to_check) and self.get_value(key_to_check) == "":
                return True
        return False

    # Sync assets
    def sync_assets(self):
        for asset_type in config.AssetType.members():
            game_asset_string = gamenaming.derive_game_asset_path_from_name(
                game_name = self.get_game(),
                asset_type = asset_type)
            game_asset_file = environment.get_locker_gaming_asset_file(
                game_category = self.get_category(),
                game_subcategory = self.get_subcategory(),
                game_name = self.get_game(),
                asset_type = asset_type)
            game_metadata_key = asset_metadata_keys[asset_type]
            if paths.is_path_file(game_asset_file):
                self.set_value(game_metadata_key, game_asset_string)
            else:
                if self.is_key_set(game_metadata_key):
                    self.delete_value(game_metadata_key)
