# Imports
import types
import os
import os.path

# Local imports
from joybox import config
from joybox import logger
from joybox import jsondata
from joybox import webpage
from joybox import webcookies
from joybox import paths
from joybox import strings
from joybox import manifest
from joybox import environment
from joybox import fileops
from joybox import metadataassetcollector
from joybox import metadatacollector

# Replace the general save folders, store install dir and user id in a path with their tokens
def convert_to_tokenized_path(
    path,
    store_type = None,
    store_user_id = None):

    # Replace tokens
    path = path.replace(paths.join_paths(config.SaveType.GENERAL, config.COMPUTER_FOLDER_GAMEDATA), config.TOKEN_GAME_INSTALL_DIR)
    path = path.replace(paths.join_paths(config.SaveType.GENERAL, config.COMPUTER_FOLDER_PUBLIC), config.TOKEN_USER_PUBLIC_DIR)
    path = path.replace(paths.join_paths(config.SaveType.GENERAL, config.COMPUTER_FOLDER_REGISTRY), config.TOKEN_USER_REGISTRY_DIR)
    if store_type:
        path = path.replace(paths.join_paths(config.SaveType.GENERAL, config.COMPUTER_FOLDER_STORE, store_type), config.TOKEN_STORE_INSTALL_DIR)
    if store_user_id:
        path = path.replace(store_user_id, config.TOKEN_STORE_USER_ID)
    path = path.replace(config.SaveType.GENERAL.val(), config.TOKEN_USER_PROFILE_DIR)

    # Return path
    return paths.normalize_file_path(path)

# Expand path tokens back into the general save folders, store install dir and user id
def convert_from_tokenized_path(
    path,
    store_type = None,
    store_user_id = None):

    # Replace tokens
    path = path.replace(config.TOKEN_GAME_INSTALL_DIR, paths.join_paths(config.SaveType.GENERAL, config.COMPUTER_FOLDER_GAMEDATA))
    path = path.replace(config.TOKEN_USER_PUBLIC_DIR, paths.join_paths(config.SaveType.GENERAL, config.COMPUTER_FOLDER_PUBLIC))
    path = path.replace(config.TOKEN_USER_REGISTRY_DIR, paths.join_paths(config.SaveType.GENERAL, config.COMPUTER_FOLDER_REGISTRY))
    if store_type:
        path = path.replace(config.TOKEN_STORE_INSTALL_DIR, paths.join_paths(config.SaveType.GENERAL, config.COMPUTER_FOLDER_STORE, store_type))
    if store_user_id:
        path = path.replace(config.TOKEN_STORE_USER_ID, store_user_id)
    path = path.replace(config.TOKEN_USER_PROFILE_DIR, config.SaveType.GENERAL.val())

    # Return path
    return paths.normalize_file_path(path)

# Copies of a path with each AppData base it contains swapped for each of that base's configured variants
def get_appdata_path_variants(path):
    variants = []
    for appdata_base, appdata_variants in config.appdata_variants.items():
        if appdata_base in path:
            for appdata_variant in appdata_variants:
                variants.append(path.replace(appdata_base, appdata_variant))
    return variants

# Base store
class StoreBase:

    # What each store sets to say which store it is and where its games are filed
    TYPE = None
    PLATFORM = ""
    SUPERCATEGORY = ""
    CATEGORY = ""
    SUBCATEGORY = ""
    KEY = ""
    IDENTIFIER_KEYS = types.MappingProxyType({})

    # Constructor
    def __init__(self):
        self.logged_in = False
        self.install_dir = None

    ############################################################
    # Store
    ############################################################

    # The store's name, as its StoreType spells it
    def get_name(self):
        return self.TYPE.val() if self.TYPE else ""

    # Which StoreType the store is
    def get_type(self):
        return self.TYPE

    # The platform its games are filed under
    def get_platform(self):
        return self.PLATFORM

    # The supercategory its games are filed under
    def get_supercategory(self):
        return self.SUPERCATEGORY

    # The category its games are filed under
    def get_category(self):
        return self.CATEGORY

    # The subcategory its games are filed under
    def get_subcategory(self):
        return self.SUBCATEGORY

    # The key its section of a game's json file is stored under
    def get_key(self):
        return self.KEY

    # Which json key identifies a game for each kind of lookup (info, install, launch...)
    def get_identifier_keys(self):
        return dict(self.IDENTIFIER_KEYS)

    # Platform to request builds for; None in the base, letting the store choose
    def get_preferred_platform(self):
        return None

    # Architecture to request builds for; None in the base, letting the store choose
    def get_preferred_architecture(self):
        return None

    # Store account login name; None in the base
    def get_account_name(self):
        return None

    # Store display user name; None in the base
    def get_user_name(self):
        return None

    # Store account email address; None in the base
    def get_email(self):
        return None

    # Where the store installs games, from the settings; None when it has none
    def get_install_dir(self):
        return self.install_dir

    # Check if store can handle installing
    def can_handle_installing(self):
        return False

    # Check if store can handle launching
    def can_handle_launching(self):
        return False

    # Check if purchases can be imported
    def can_import_purchases(self):
        return False

    # Check if purchases can be downloaded
    def can_download_purchases(self):
        return False

    ############################################################
    # Identifiers
    ############################################################

    # Json key that identifies a game for this lookup type; None when the store has none
    def get_identifier_key(self, identifier_type):
        return self.get_identifier_keys().get(identifier_type)

    # Json key identifying a game when fetching its store info
    def get_info_identifier_key(self):
        return self.get_identifier_key(config.StoreIdentifierType.INFO)

    # Json key identifying a game when installing it
    def get_install_identifier_key(self):
        return self.get_identifier_key(config.StoreIdentifierType.INSTALL)

    # Json key identifying a game when launching it
    def get_launch_identifier_key(self):
        return self.get_identifier_key(config.StoreIdentifierType.LAUNCH)

    # Json key identifying a game when downloading it
    def get_download_identifier_key(self):
        return self.get_identifier_key(config.StoreIdentifierType.DOWNLOAD)

    # Json key identifying a game when looking up its artwork
    def get_asset_identifier_key(self):
        return self.get_identifier_key(config.StoreIdentifierType.ASSET)

    # Json key identifying a game when collecting its metadata
    def get_metadata_identifier_key(self):
        return self.get_identifier_key(config.StoreIdentifierType.METADATA)

    # Json key identifying a game when building its store page url
    def get_page_identifier_key(self):
        return self.get_identifier_key(config.StoreIdentifierType.PAGE)

    # True for any non-empty string; stores override per lookup type
    def is_valid_identifier(self, identifier):
        return isinstance(identifier, str) and len(identifier) > 0

    # Whether the value can look up store info; any non-empty string in the base
    def is_valid_info_identifier(self, identifier):
        return self.is_valid_identifier(identifier)

    # Whether the value can install a game; any non-empty string in the base
    def is_valid_install_identifier(self, identifier):
        return self.is_valid_identifier(identifier)

    # Whether the value can launch a game; any non-empty string in the base
    def is_valid_launch_identifier(self, identifier):
        return self.is_valid_identifier(identifier)

    # Whether the value can download a game; any non-empty string in the base
    def is_valid_download_identifier(self, identifier):
        return self.is_valid_identifier(identifier)

    # Whether the value can look up artwork; any non-empty string in the base
    def is_valid_asset_identifier(self, identifier):
        return self.is_valid_identifier(identifier)

    # Whether the value can look up metadata; any non-empty string in the base
    def is_valid_metadata_identifier(self, identifier):
        return self.is_valid_identifier(identifier)

    # Whether the value can build a store page url; any non-empty string in the base
    def is_valid_page_identifier(self, identifier):
        return self.is_valid_identifier(identifier)

    ############################################################
    # Connection
    ############################################################

    # Check if logged in
    def is_logged_in(self):
        return self.logged_in

    # Record whether a sign-in succeeded this run
    def set_logged_in(self, value):
        self.logged_in = value

    # Get files the purchase listing's saved sign-in is kept in; empty when it cannot be checked
    def get_login_files(self):
        return []

    # Check if the purchase listing has a saved sign-in to use
    def has_saved_login(self):
        return all(paths.is_path_file(login_file) for login_file in self.get_login_files())

    # Get how to sign in again
    def get_login_hint(self):
        return "login_game_stores -c %s -s \"%s\"" % (self.get_category(), self.get_subcategory())

    # Get the config dir command-line tools keep their settings in
    def get_user_config_dir(self):
        return os.environ.get("XDG_CONFIG_HOME") or paths.expand_path("~/.config")

    # Sign in to the store; the base has no sign-in and returns False
    def login(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        del verbose, pretend_run, exit_on_failure
        return False

    # Start a Selenium web driver for scraping the store, headless when asked
    def web_connect(
        self,
        headless = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Create web driver
        return webpage.create_web_driver(
            make_headless = headless,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Shut down a web driver from web_connect
    def web_disconnect(
        self,
        web_driver,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Destroy web driver
        return webpage.destroy_web_driver(
            driver = web_driver,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Saved browser cookie file named after the store
    def get_cookie_file(self):
        return webcookies.get_cookie_file(self.get_name().lower())

    ############################################################
    # Versions
    ############################################################

    # Build id from the game's latest store json; None when it cannot be fetched
    def get_latest_version(
        self,
        identifier,
        branch = None,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get latest jsondata
        latest_jsondata = self.get_latest_jsondata(
            identifier = identifier,
            branch = branch,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not latest_jsondata:
            return None

        # Return version
        return latest_jsondata.get_value(config.JSON_KEY_STORE_BUILDID)

    ############################################################
    # Page
    ############################################################

    # Store page url for a game; None in the base
    def get_latest_url(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        del identifier, verbose, pretend_run, exit_on_failure

    ############################################################
    # Purchases
    ############################################################

    # Get purchases cache directory
    def get_purchases_cache_dir(self):
        cache_dir = environment.get_cache_purchases_dir()
        fileops.make_directory(src = cache_dir)
        return cache_dir

    # Games the account owns, from the store; empty in the base
    def get_latest_purchases(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        del verbose, pretend_run, exit_on_failure
        return []

    ############################################################
    # Json
    ############################################################

    # Store json for this platform with empty paths and keys and the default build id
    def create_default_jsondata(self):
        json_data = jsondata.JsonData({}, self.get_platform())
        json_data.set_value(config.JSON_KEY_STORE_PATHS, [])
        json_data.set_value(config.JSON_KEY_STORE_KEYS, [])
        json_data.set_value(config.JSON_KEY_STORE_BUILDID, config.DEFAULT_BUILDID)
        return json_data

    # Merge Ludusavi manifest save paths and keys into the json and drop C:, store install
    # dir and store user id paths; returns the json sorted
    def augment_jsondata(
        self,
        json_data,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get existing paths and keys
        del verbose, pretend_run, exit_on_failure
        game_paths = list(json_data.get_value(config.JSON_KEY_STORE_PATHS))
        game_keys = list(json_data.get_value(config.JSON_KEY_STORE_KEYS))

        # Augment by manifest
        manifest_entry = manifest.get_manifest_instance().find_entry_by_name(
            name = identifier)
        if manifest_entry:
            base_path = config.TOKEN_GAME_INSTALL_DIR
            manifest_paths = manifest_entry.get_paths(base_path)
            game_paths = list(set(game_paths).union(manifest_paths))
            game_keys = list(set(game_keys).union(manifest_entry.get_keys()))

        # Remove invalid paths
        game_paths = [item for item in game_paths if not item.startswith("C:")]
        game_paths = [item for item in game_paths if config.TOKEN_STORE_INSTALL_DIR not in item]
        game_paths = [item for item in game_paths if config.TOKEN_STORE_USER_ID not in item]

        # Remove duplicate paths
        game_paths = list(dict.fromkeys(game_paths))

        # Save paths and keys
        json_data.set_value(config.JSON_KEY_STORE_PATHS, strings.sort_strings(game_paths))
        json_data.set_value(config.JSON_KEY_STORE_KEYS, strings.sort_strings(game_keys))
        return json_data

    # Default store json augmented from the manifest; None for an invalid info identifier
    def get_latest_jsondata(
        self,
        identifier,
        branch = None,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check identifier
        del branch
        if not self.is_valid_info_identifier(identifier):
            logger.log_warning("Info identifier '%s' was not valid" % identifier)
            return None

        # Build jsondata
        return self.augment_jsondata(
            json_data = self.create_default_jsondata(),
            identifier = identifier,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    ############################################################
    # Metadata
    ############################################################

    # Metadata gathered from every collector for the game; None for an invalid identifier
    def get_latest_metadata(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        del exit_on_failure

        # Check identifier
        if not self.is_valid_metadata_identifier(identifier):
            logger.log_warning("Metadata identifier '%s' was not valid" % identifier)
            return None

        # Collect metadata entry
        return metadatacollector.collect_metadata_from_all(
            game_platform = self.get_platform(),
            game_name = identifier,
            keys_to_check = config.metadata_keys_downloadable,
            verbose = verbose,
            pretend_run = pretend_run)

    ############################################################
    # Assets
    ############################################################

    # Url of an artwork asset found by the asset collectors; None for an invalid identifier
    def get_latest_asset_url(
        self,
        identifier,
        asset_type,
        game_name = None,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check identifier
        if not self.is_valid_asset_identifier(identifier):
            logger.log_warning("Asset identifier '%s' was not valid" % identifier)
            return None

        # Collect asset url
        return metadataassetcollector.find_metadata_asset(
            game_platform = self.get_platform(),
            game_name = game_name if game_name else identifier,
            asset_type = asset_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    ############################################################
    # Install
    ############################################################

    # Check if installed
    def is_installed(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        del identifier, verbose, pretend_run, exit_on_failure
        return False

    # Install a game through the store client; False in the base
    def install(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        del identifier, verbose, pretend_run, exit_on_failure
        return False

    # Remove a game through the store client; False in the base
    def uninstall(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        del identifier, verbose, pretend_run, exit_on_failure
        return False

    ############################################################
    # Launch
    ############################################################

    # Start a game through the store client; False in the base
    def launch(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        del identifier, verbose, pretend_run, exit_on_failure
        return False

    ############################################################
    # Download
    ############################################################

    # Download a game's files into output_dir; False in the base
    def download(
        self,
        identifier,
        output_dir,
        output_name = None,
        branch = None,
        clean_output = False,
        show_progress = False,
        skip_existing = False,
        skip_identical = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        del (identifier, output_dir, output_name, branch, clean_output, show_progress,
            skip_existing, skip_identical, verbose, pretend_run, exit_on_failure)
        return False

    ############################################################
    # Paths
    ############################################################

    # Real locations for each path token: public dir, USERPROFILE and the store install dir; registry has none
    def build_path_translation_map(self, appid = None, appname = None):

        # Build translation map
        del appid, appname
        translation_map = {}

        # Add registry dir
        translation_map[config.TOKEN_USER_REGISTRY_DIR] = []

        # Add user public dir
        translation_map[config.TOKEN_USER_PUBLIC_DIR] = []
        translation_map[config.TOKEN_USER_PUBLIC_DIR].append("C:\\Users\\Public")

        # Add user profile dir
        translation_map[config.TOKEN_USER_PROFILE_DIR] = []
        if "USERPROFILE" in os.environ:
            translation_map[config.TOKEN_USER_PROFILE_DIR].append(os.environ["USERPROFILE"])

        # Add store install dir
        translation_map[config.TOKEN_STORE_INSTALL_DIR] = []
        translation_map[config.TOKEN_STORE_INSTALL_DIR].append(self.get_install_dir())

        # Return translation map
        return translation_map

    # The paths plus copies with each AppData base swapped for its configured variants
    def add_path_variants(self, path_list = None):

        # Copy the input
        new_paths = list(path_list) if path_list else []

        # Add AppData variants
        for path in sorted(new_paths):
            new_paths += get_appdata_path_variants(path)
        return new_paths

    ############################################################
