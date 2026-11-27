# Imports
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

# Convert to tokenized path
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

# Convert from tokenized path
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

# Base store
class StoreBase:

    # Constructor
    def __init__(self):
        self.logged_in = False

    ############################################################
    # Store
    ############################################################

    # Get name
    def get_name(self):
        return ""

    # Get type
    def get_type(self):
        return None

    # Get platform
    def get_platform(self):
        return ""

    # Get supercategory
    def get_supercategory(self):
        return ""

    # Get category
    def get_category(self):
        return ""

    # Get subcategory
    def get_subcategory(self):
        return ""

    # Get key
    def get_key(self):
        return ""

    # Get identifier keys
    def get_identifier_keys(self):
        return {}

    # Get preferred platform
    def get_preferred_platform(self):
        return None

    # Get preferred architecture
    def get_preferred_architecture(self):
        return None

    # Get account name
    def get_account_name(self):
        return None

    # Get user name
    def get_user_name(self):
        return None

    # Get email
    def get_email(self):
        return None

    # Get install dir
    def get_install_dir(self):
        return None

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

    # Get identifier key
    def get_identifier_key(self, identifier_type):
        return self.get_identifier_keys().get(identifier_type)

    # Get info identifier key
    def get_info_identifier_key(self):
        return self.get_identifier_key(config.StoreIdentifierType.INFO)

    # Get install identifier key
    def get_install_identifier_key(self):
        return self.get_identifier_key(config.StoreIdentifierType.INSTALL)

    # Get launch identifier key
    def get_launch_identifier_key(self):
        return self.get_identifier_key(config.StoreIdentifierType.LAUNCH)

    # Get download identifier key
    def get_download_identifier_key(self):
        return self.get_identifier_key(config.StoreIdentifierType.DOWNLOAD)

    # Get asset identifier key
    def get_asset_identifier_key(self):
        return self.get_identifier_key(config.StoreIdentifierType.ASSET)

    # Get metadata identifier key
    def get_metadata_identifier_key(self):
        return self.get_identifier_key(config.StoreIdentifierType.METADATA)

    # Get page identifier key
    def get_page_identifier_key(self):
        return self.get_identifier_key(config.StoreIdentifierType.PAGE)

    # Is valid identifier
    def is_valid_identifier(self, identifier):
        return isinstance(identifier, str) and len(identifier) > 0

    # Is valid info identifier
    def is_valid_info_identifier(self, identifier):
        return self.is_valid_identifier(identifier)

    # Is valid install identifier
    def is_valid_install_identifier(self, identifier):
        return self.is_valid_identifier(identifier)

    # Is valid launch identifier
    def is_valid_launch_identifier(self, identifier):
        return self.is_valid_identifier(identifier)

    # Is valid download identifier
    def is_valid_download_identifier(self, identifier):
        return self.is_valid_identifier(identifier)

    # Is valid asset identifier
    def is_valid_asset_identifier(self, identifier):
        return self.is_valid_identifier(identifier)

    # Is valid metadata identifier
    def is_valid_metadata_identifier(self, identifier):
        return self.is_valid_identifier(identifier)

    # Is valid page identifier
    def is_valid_page_identifier(self, identifier):
        return self.is_valid_identifier(identifier)

    ############################################################
    # Connection
    ############################################################

    # Check if logged in
    def is_logged_in(self):
        return self.logged_in

    # Set logged in
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

    # Login
    def login(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        del verbose, pretend_run, exit_on_failure
        return False

    # Web connect
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

    # Web disconnect
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

    # Get cookie file
    def get_cookie_file(self):
        return webcookies.get_cookie_file(self.get_name().lower())

    ############################################################
    # Versions
    ############################################################

    # Get latest version
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

    # Get latest url
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

    # Get purchases
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

    # Create default jsondata
    def create_default_jsondata(self):
        json_data = jsondata.JsonData({}, self.get_platform())
        json_data.set_value(config.JSON_KEY_STORE_PATHS, [])
        json_data.set_value(config.JSON_KEY_STORE_KEYS, [])
        json_data.set_value(config.JSON_KEY_STORE_BUILDID, config.DEFAULT_BUILDID)
        return json_data

    # Augment jsondata
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

        # Fix malformed paths with duplicate segments
        cleaned_paths = []
        for path in game_paths:
            parts = path.split('/')
            cleaned_parts = []
            i = 0
            while i < len(parts):
                found_repeat = False
                for seq_len in range(1, (len(parts) - i) // 2 + 1):
                    sequence = parts[i:i+seq_len]
                    next_sequence = parts[i+seq_len:i+seq_len*2]
                    if sequence == next_sequence and len(sequence) > 0:
                        cleaned_parts.extend(sequence)
                        i += seq_len * 2
                        found_repeat = True
                        break
                if not found_repeat:
                    cleaned_parts.append(parts[i])
                    i += 1
            cleaned_path = '/'.join(cleaned_parts)
            cleaned_paths.append(cleaned_path)
        game_paths = cleaned_paths

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

    # Get latest jsondata
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

    # Get latest metadata
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
        from joybox import metadatacollector
        return metadatacollector.collect_metadata_from_all(
            game_platform = self.get_platform(),
            game_name = identifier,
            keys_to_check = config.metadata_keys_downloadable,
            verbose = verbose,
            pretend_run = pretend_run)

    ############################################################
    # Assets
    ############################################################

    # Get latest asset url
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
        from joybox import metadataassetcollector
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

    # Install
    def install(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        del identifier, verbose, pretend_run, exit_on_failure
        return False

    # Uninstall
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

    # Launch
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

    # Download
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

    # Build path translation map
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

    # Add path variants
    def add_path_variants(self, paths = None):

        # Copy the input
        new_paths = list(paths) if paths else []

        # Add AppData variants
        for path in sorted(new_paths):
            for appdata_base in config.appdata_variants.keys():
                if appdata_base in path:
                    for appdata_variant in config.appdata_variants[appdata_base]:
                        new_paths.append(path.replace(appdata_base, appdata_variant))
        return new_paths

    ############################################################
