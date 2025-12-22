# Imports
import os, os.path
import sys

# Local imports
import config
import logger
import jsondata
import webpage
import metadatacollector
import paths
import strings
import metadataassetcollector
import manifest

# Create tokenized path
def create_tokenized_path(path, base_path = None):

    # Replace tokens
    new_path = path
    new_path = new_path.replace("{EpicID}", "<storeUserId>")
    new_path = new_path.replace("{EpicId}", "<storeUserId>")
    new_path = new_path.replace("{UserDir}", "<home>")
    new_path = new_path.replace("{UserProfile}", "<home>")
    new_path = new_path.replace("%USERPROFILE%", "<home>")
    new_path = new_path.replace("%userprofile%", "<home>")
    new_path = new_path.replace("{InstallDir}", "<base>")
    new_path = new_path.replace("{UserSavedGames}", "<home>/Saved Games")
    new_path = new_path.replace("{AppData}/../Roaming", "<winAppData>")
    new_path = new_path.replace("{AppData}/../Roaming".lower(), "<winAppData>")
    new_path = new_path.replace("{AppData}/../LocalLow", "<winAppDataLocalLow>")
    new_path = new_path.replace("{AppData}/../LocalLow".lower(), "<winAppDataLocalLow>")
    new_path = new_path.replace("{AppData}", "<winLocalAppData>")
    new_path = new_path.replace("<storeUserId>", config.token_store_user_id)
    new_path = new_path.replace("<winPublic>", config.token_user_public_dir)
    new_path = new_path.replace("<winDir>", config.token_user_profile_dir + "/AppData/Local/VirtualStore")
    new_path = new_path.replace("<winAppData>", config.token_user_profile_dir + "/AppData/Roaming")
    new_path = new_path.replace("<winAppDataLocalLow>", config.token_user_profile_dir + "/AppData/LocalLow")
    new_path = new_path.replace("<winLocalAppData>", config.token_user_profile_dir + "/AppData/Local")
    new_path = new_path.replace("<winProgramData>", config.token_user_profile_dir + "/AppData/Local/VirtualStore")
    new_path = new_path.replace("<winDocuments>", config.token_user_profile_dir + "/Documents")
    new_path = new_path.replace("<home>", config.token_user_profile_dir)
    new_path = new_path.replace("<root>", config.token_store_install_dir)
    if paths.is_path_valid(base_path):
        new_path = new_path.replace("<base>", base_path)
    else:
        new_path = new_path.replace("<base>", config.token_game_install_dir)

    # Return path
    return paths.normalize_file_path(new_path)

# Convert to tokenized path
def convert_to_tokenized_path(
    path,
    store_type = None,
    store_user_id = None):

    # Replace tokens
    path = path.replace(paths.join_paths(config.SaveType.GENERAL, config.computer_folder_gamedata), config.token_game_install_dir)
    path = path.replace(paths.join_paths(config.SaveType.GENERAL, config.computer_folder_public), config.token_user_public_dir)
    path = path.replace(paths.join_paths(config.SaveType.GENERAL, config.computer_folder_registry), config.token_user_registry_dir)
    if store_type:
        path = path.replace(paths.join_paths(config.SaveType.GENERAL, config.computer_folder_store, store_type), config.token_store_install_dir)
    if store_user_id:
        path = path.replace(store_user_id, config.token_store_user_id)
    path = path.replace(config.SaveType.GENERAL.val(), config.token_user_profile_dir)

    # Return path
    return paths.normalize_file_path(path)

# Convert from tokenized path
def convert_from_tokenized_path(
    path,
    store_type = None,
    store_user_id = None):

    # Replace tokens
    path = path.replace(config.token_game_install_dir, paths.join_paths(config.SaveType.GENERAL, config.computer_folder_gamedata))
    path = path.replace(config.token_user_public_dir, paths.join_paths(config.SaveType.GENERAL, config.computer_folder_public))
    path = path.replace(config.token_user_registry_dir, paths.join_paths(config.SaveType.GENERAL, config.computer_folder_registry))
    if store_type:
        path = path.replace(config.token_store_install_dir, paths.join_paths(config.SaveType.GENERAL, config.computer_folder_store, store_type))
    if store_user_id:
        path = path.replace(config.token_store_user_id, store_user_id)
    path = path.replace(config.token_user_profile_dir, config.SaveType.GENERAL.val())

    # Return path
    return paths.normalize_file_path(path)

# Base store
class StoreBase:

    # Constructor
    def __init__(self):
        self.is_logged_in = False

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
        return isinstance(identifier, str) and len(identifier)

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
        return self.is_logged_in

    # Set logged in
    def set_logged_in(self, value):
        self.is_logged_in = value

    # Login
    def login(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
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
        return webpage.get_cookie_file(self.get_name().lower())

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
        return latest_jsondata.get_value(config.json_key_store_buildid)

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
        return None

    ############################################################
    # Purchases
    ############################################################

    # Get purchases
    def get_latest_purchases(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        return []

    ############################################################
    # Json
    ############################################################

    # Create default jsondata
    def create_default_jsondata(self):
        json_data = jsondata.JsonData({}, self.get_platform())
        json_data.set_value(config.json_key_store_paths, [])
        json_data.set_value(config.json_key_store_keys, [])
        json_data.set_value(config.json_key_store_buildid, config.default_buildid)
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
        game_paths = list(json_data.get_value(config.json_key_store_paths))
        game_keys = list(json_data.get_value(config.json_key_store_keys))

        # Augment by manifest
        manifest_entry = manifest.GetManifestInstance().find_entry_by_name(
            name = identifier,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if manifest_entry:
            base_path = config.token_game_install_dir
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
        game_paths = [item for item in game_paths if config.token_store_install_dir not in item]
        game_paths = [item for item in game_paths if config.token_store_user_id not in item]

        # Remove duplicate paths
        game_paths = list(dict.fromkeys(game_paths))

        # Save paths and keys
        json_data.set_value(config.json_key_store_paths, strings.sort_strings(game_paths))
        json_data.set_value(config.json_key_store_keys, strings.sort_strings(game_keys))
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

        # Check identifier
        if not self.is_valid_metadata_identifier(identifier):
            logger.log_warning("Metadata identifier '%s' was not valid" % identifier)
            return None

        # Collect metadata entry
        return metadatacollector.CollectMetadataFromAll(
            game_platform = self.get_platform(),
            game_name = identifier,
            keys_to_check = config.metadata_keys_downloadable,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

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
        return metadataassetcollector.FindMetadataAsset(
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
        return False

    # Install
    def install(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        return False

    # Uninstall
    def uninstall(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
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
        return False

    ############################################################
    # Paths
    ############################################################

    # Build path translation map
    def build_path_translation_map(self, appid = None, appname = None):

        # Build translation map
        translation_map = {}

        # Add registry dir
        translation_map[config.token_user_registry_dir] = []

        # Add user public dir
        translation_map[config.token_user_public_dir] = []
        translation_map[config.token_user_public_dir].append("C:\\Users\\Public")

        # Add user profile dir
        translation_map[config.token_user_profile_dir] = []
        if "USERPROFILE" in os.environ:
            translation_map[config.token_user_profile_dir].append(os.environ["USERPROFILE"])

        # Add store install dir
        translation_map[config.token_store_install_dir] = []
        translation_map[config.token_store_install_dir].append(self.get_install_dir())

        # Return translation map
        return translation_map

    # Add path variants
    def add_path_variants(self, paths = []):

        # Add AppData variants
        for path in sorted(paths):
            for appdata_base in config.appdata_variants.keys():
                if appdata_base in path:
                    for appdata_variant in config.appdata_variants[appdata_base]:
                        paths.append(path.replace(appdata_base, appdata_variant))
        return paths

    ############################################################
