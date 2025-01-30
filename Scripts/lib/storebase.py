# Imports
import os, os.path
import sys

# Local imports
import config
import system
import environment
import saves
import gameinfo
import jsondata
import network
import launcher
import collection
import programs
import webpage
import metadataentry
import metadatacollector

# Translate store path
def TranslateStorePath(path, base_path = None):

    # Replace tokens
    new_path = path
    new_path = new_path.replace("{EpicID}", "<storeUserId>")
    new_path = new_path.replace("{EpicId}", "<storeUserId>")
    new_path = new_path.replace("{UserDir}", "<home>")
    new_path = new_path.replace("{InstallDir}", "<base>")
    new_path = new_path.replace("{UserSavedGames}", "<home>/Saved Games")
    new_path = new_path.replace("{AppData}/../Roaming", "<winAppData>")
    new_path = new_path.replace("{AppData}/../Roaming".lower(), "<winAppData>")
    new_path = new_path.replace("{AppData}/../LocalLow", "<winAppDataLocalLow>")
    new_path = new_path.replace("{AppData}/../LocalLow".lower(), "<winAppDataLocalLow>")
    new_path = new_path.replace("{AppData}", "<winLocalAppData>")
    new_path = new_path.replace("<storeUserId>", config.token_store_user_id)
    new_path = new_path.replace("<winPublic>", config.token_user_public_dir)
    new_path = new_path.replace("<winDir>", "%s/AppData/Local/VirtualStore" % config.token_user_profile_dir)
    new_path = new_path.replace("<winAppData>", "%s/AppData/Roaming" % config.token_user_profile_dir)
    new_path = new_path.replace("<winAppDataLocalLow>", "%s/AppData/LocalLow" % config.token_user_profile_dir)
    new_path = new_path.replace("<winLocalAppData>", "%s/AppData/Local" % config.token_user_profile_dir)
    new_path = new_path.replace("<winProgramData>", "%s/AppData/Local/VirtualStore" % config.token_user_profile_dir)
    new_path = new_path.replace("<winDocuments>", "%s/Documents" % config.token_user_profile_dir)
    new_path = new_path.replace("<home>", config.token_user_profile_dir)
    new_path = new_path.replace("<root>", config.token_store_install_dir)
    if system.IsPathValid(base_path):
        new_path = new_path.replace("<base>", "%s/%s" % (config.token_store_install_dir, base_path))
    else:
        new_path = new_path.replace("<base>", config.token_store_install_dir)

    # Replace wildcards
    if "/**/" in new_path:
        for new_path_part in new_path.split("/**/"):
            new_path = new_path_part
            break
    if "*" in system.GetFilenameFile(new_path):
        new_path = system.GetFilenameDirectory(new_path)

    # Return path
    return system.NormalizeFilePath(new_path)

# Base store
class StoreBase:

    # Constructor
    def __init__(self):
        self.manifest = None

    ############################################################
    # Store
    ############################################################

    # Get name
    def GetName(self):
        return ""

    # Get type
    def GetType(self):
        return None

    # Get platform
    def GetPlatform(self):
        return ""

    # Get supercategory
    def GetSupercategory(self):
        return ""

    # Get category
    def GetCategory(self):
        return ""

    # Get subcategory
    def GetSubcategory(self):
        return ""

    # Get key
    def GetKey(self):
        return ""

    # Get identifier
    def GetIdentifier(self, json_wrapper, identifier_type):
        return ""

    # Get info identifier
    def GetInfoIdentifier(self, json_wrapper):
        return self.GetIdentifier(json_wrapper, config.StoreIdentifierType.INFO)

    # Get install identifier
    def GetInstallIdentifier(self, json_wrapper):
        return self.GetIdentifier(json_wrapper, config.StoreIdentifierType.INSTALL)

    # Get launch identifier
    def GetLaunchIdentifier(self, json_wrapper):
        return self.GetIdentifier(json_wrapper, config.StoreIdentifierType.LAUNCH)

    # Get download identifier
    def GetDownloadIdentifier(self, json_wrapper):
        return self.GetIdentifier(json_wrapper, config.StoreIdentifierType.DOWNLOAD)

    # Get asset identifier
    def GetAssetIdentifier(self, json_wrapper):
        return self.GetIdentifier(json_wrapper, config.StoreIdentifierType.ASSET)

    # Get metadata identifier
    def GetMetadataIdentifier(self, json_wrapper):
        return self.GetIdentifier(json_wrapper, config.StoreIdentifierType.METADATA)

    # Is valid identifier
    def IsValidIdentifier(self, identifier):
        return isinstance(identifier, str) and len(identifier)

    # Get platform
    def GetPlatform(self):
        return None

    # Get architecture
    def GetArchitecture(self):
        return None

    # Get account name
    def GetAccountName(self):
        return None

    # Get user name
    def GetUserName(self):
        return None

    # Get install dir
    def GetInstallDir(self):
        return None

    ############################################################
    # Manifest
    ############################################################

    # Load manifest
    def LoadManifest(self, verbose = False, pretend_run = False, exit_on_failure = False):
        self.manifest = system.ReadYamlFile(
            src = programs.GetToolPathConfigValue("LudusaviManifest", "yaml"),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    ############################################################
    # Connection
    ############################################################

    # Login
    def Login(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        return False

    # Web connect
    def WebConnect(
        self,
        headless = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Create web driver
        return webpage.CreateWebDriver(
            make_headless = headless,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Web disconnect
    def WebDisconnect(
        self,
        web_driver,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Destroy web driver
        return webpage.DestroyWebDriver(
            driver = web_driver,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Get cookie file
    def GetCookieFile(self):
        return webpage.GetCookieFile(self.GetName().lower())

    ############################################################
    # Versions
    ############################################################

    # Get versions
    def GetVersions(
        self,
        game_info,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get latest jsondata
        latest_jsondata = self.GetLatestJsondata(
            identifier = self.GetInfoIdentifier(game_info.get_wrapped_value(self.GetKey())),
            branch = game_info.get_store_branchid(self.GetKey()),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not latest_jsondata:
            return (None, None)

        # Return versions
        local_version = game_info.get_store_buildid(self.GetKey())
        remote_version = latest_jsondata.get_value(config.json_key_store_buildid)
        return (local_version, remote_version)

    ############################################################
    # Page
    ############################################################

    # Get latest url
    def GetLatestUrl(
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
    def GetPurchases(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        return []

    # Display purchases
    def DisplayPurchases(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        return False

    # Import purchases
    def ImportPurchases(
        self,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get all purchases
        purchases = self.GetPurchases(
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not purchases:
            return False

        # Get all ignores
        ignores = collection.GetGameJsonIgnoreEntries(
            game_supercategory = self.GetSupercategory(),
            game_category = self.GetCategory(),
            game_subcategory = self.GetSubcategory(),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Import each purchase
        for purchase in purchases:
            purchase_appid = purchase.get_value(config.json_key_store_appid)
            purchase_appname = purchase.get_value(config.json_key_store_appname)
            purchase_appurl = purchase.get_value(config.json_key_store_appurl)
            purchase_name = purchase.get_value(config.json_key_store_name)
            purchase_identifiers = [
                purchase_appid,
                purchase_appname,
                purchase_appurl
            ]

            # Get info identifier
            info_identifier = self.GetInfoIdentifier(purchase)
            if not info_identifier:
                continue

            # Check if json file already exists
            found_file = self.FindPurchases(
                identifiers = purchase_identifiers,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if found_file:
                continue

            # Check if this should be ignored
            if info_identifier in ignores.keys():
                continue

            # Determine if this should be imported
            system.LogInfo("Found new potential entry:")
            if purchase_appid:
                system.LogInfo(" - Appid:\t" + purchase_appid)
            if purchase_appname:
                system.LogInfo(" - Appname:\t" + purchase_appname)
            if purchase_appurl:
                system.LogInfo(" - Appurl:\t" + purchase_appurl)
            if purchase_name:
                system.LogInfo(" - Name:\t" + purchase_name)
            should_import = system.PromptForValue("Import this? (n to skip, i to ignore)", default_value = "n")
            if should_import.lower() == "n":
                continue

            # Add to ignore
            if should_import.lower() == "i":
                collection.AddGameJsonIgnoreEntry(
                    game_supercategory = self.GetSupercategory(),
                    game_category = self.GetCategory(),
                    game_subcategory = self.GetSubcategory(),
                    game_identifier = info_identifier,
                    game_name = purchase_name,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
                continue

            # Prompt for entry name
            default_name = gameinfo.DeriveGameNameFromRegularName(purchase_name)
            entry_name = system.PromptForValue("Choose entry name", default_value = default_name)

            # Get appurl if necessary
            if not purchase_appurl and purchase_name:
                purchase_appurl = self.GetLatestUrl(
                    identifier = purchase_name,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
                if purchase_appurl:
                    purchase.set_value(config.json_key_store_appurl, purchase_appurl)

            # Create json file
            success = collection.CreateGameJsonFile(
                game_supercategory = self.GetSupercategory(),
                game_category = self.GetCategory(),
                game_subcategory = self.GetSubcategory(),
                game_name = entry_name,
                game_root = environment.GetLockerGamingFilesDir(
                    game_supercategory = self.GetSupercategory(),
                    game_category = self.GetCategory(),
                    game_subcategory = self.GetSubcategory(),
                    game_name = entry_name),
                initial_data = {self.GetKey(): purchase.get_data()},
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Unable to create json file for game '%s'" % entry_name)
                return False

            # Add metadata entry
            success = collection.AddMetadataEntry(
                game_supercategory = self.GetSupercategory(),
                game_category = self.GetCategory(),
                game_subcategory = self.GetSubcategory(),
                game_name = entry_name,
                game_url = purchase_appurl,
                initial_data = self.GetLatestMetadata(
                    identifier = self.GetMetadataIdentifier(purchase),
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Unable to add metadata entry for game '%s'" % entry_name)
                return False

            # Download assets
            for asset_type in config.AssetMinType.members():
                success = collection.DownloadMetadataAsset(
                    game_supercategory = self.GetSupercategory(),
                    game_category = self.GetCategory(),
                    game_subcategory = self.GetSubcategory(),
                    game_name = entry_name,
                    asset_url = self.GetLatestAssetUrl(
                        identifier = self.GetAssetIdentifier(purchase),
                        asset_type = asset_type,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure),
                    asset_type = asset_type,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
                if not success:
                    system.LogWarning("Unable to download asset %s for game '%s'" % (asset_type, entry_name))

            # Update metadata entry
            success = collection.UpdateMetadataEntry(
                game_supercategory = self.GetSupercategory(),
                game_category = self.GetCategory(),
                game_subcategory = self.GetSubcategory(),
                game_name = entry_name,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogWarning("Unable to update metadata entry for game '%s'" % entry_name)

        # Should be successful
        return True

    # Find purchases
    def FindPurchases(
        self,
        identifiers,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        json_files = system.BuildFileListByExtensions(
            root = environment.GetJsonMetadataDir(self.GetSupercategory(), self.GetCategory(), self.GetSubcategory()),
            extensions = [".json"])
        for json_file in json_files:
            json_data = system.ReadJsonFile(
                src = json_file,
                exit_on_failure = exit_on_failure)
            if self.GetKey() not in json_data:
                continue
            json_store_data = json_data[self.GetKey()]
            for appdata_key in config.json_keys_store_appdata:
                if appdata_key not in json_store_data:
                    continue
                for identifier in identifiers:
                    if identifier and identifier == json_store_data[appdata_key]:
                        return json_file
        return None

    ############################################################
    # Json
    ############################################################

    # Get latest jsondata
    def GetLatestJsondata(
        self,
        identifier,
        branch = None,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        return None

    # Update json
    def UpdateJson(
        self,
        game_info,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get current jsondata
        current_jsondata = game_info.read_wrapped_json_data(
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not current_jsondata:
            return False

        # Get latest jsondata
        latest_jsondata = self.GetLatestJsondata(
            identifier = self.GetInfoIdentifier(game_info.get_wrapped_value(self.GetKey())),
            branch = game_info.get_store_branchid(self.GetKey()),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not latest_jsondata:
            return False

        # Update current data
        for store_key in config.json_keys_store_subdata:
            if latest_jsondata.has_key(store_key):
                current_jsondata.fill_subvalue(self.GetKey(), store_key, latest_jsondata.get_value(store_key))
                if store_key == config.json_key_store_paths:
                    paths = current_jsondata.get_subvalue(self.GetKey(), store_key, [])
                    paths = system.PruneChildPaths(paths)
                    current_jsondata.set_subvalue(self.GetKey(), store_key, paths)

        # Write back changes
        success = game_info.write_wrapped_json_data(
            json_wrapper = current_jsondata,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return success

    ############################################################
    # Metadata
    ############################################################

    # Get latest metadata
    def GetLatestMetadata(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check identifier
        if not self.IsValidIdentifier(identifier):
            return None

        # Collect metadata entry
        return metadatacollector.CollectMetadataFromAll(
            game_platform = self.GetPlatform(),
            game_name = identifier,
            keys_to_check = config.metadata_keys_downloadable,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Update metadata
    def UpdateMetadata(
        self,
        game_info,
        keys = [],
        force = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get current metadata
        current_metadata = game_info.get_metadata()
        if not current_metadata:
            return False

        # Determine if update is needed
        should_update = False
        if force:
            should_update = True
        else:
            if isinstance(keys, list) and len(keys) > 0:
                should_update = current_metadata.is_missing_data(keys)
            else:
                should_update = current_metadata.is_missing_data(config.metadata_keys_downloadable)
        if not should_update:
            return True

        # Get latest metadata
        latest_metadata = self.GetLatestMetadata(
            identifier = self.GetMetadataIdentifier(game_info.get_wrapped_value(self.GetKey())),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not latest_metadata:
            return False

        # Update current data
        if isinstance(latest_metadata, metadataentry.MetadataEntry):
            current_metadata.merge(latest_metadata)

        # Sync assets
        current_metadata.sync_assets()

        # Write back changes
        game_info.set_metadata(current_metadata)
        game_info.write_metadata()
        return True

    ############################################################
    # Assets
    ############################################################

    # Get latest asset url
    def GetLatestAssetUrl(
        self,
        identifier,
        asset_type,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        return None

    # Download asset
    def DownloadAsset(
        self,
        game_info,
        asset_type,
        force = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check if asset exists
        asset_exists = collection.DoesMetadataAssetExist(
            game_supercategory = game_info.get_supercategory(),
            game_category = game_info.get_category(),
            game_subcategory = game_info.get_subcategory(),
            game_name = game_info.get_name(),
            asset_type = asset_type)

        # Check if asset should be downloaded
        should_download = False
        if force or not asset_exists:
            should_download = True
        if not should_download:
            return True

        # Get latest asset url
        asset_url = self.GetLatestAssetUrl(
            identifier = self.GetAssetIdentifier(game_info.get_wrapped_value(self.GetKey())),
            asset_type = asset_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Download metadata asset
        success = collection.DownloadMetadataAsset(
            game_supercategory = game_info.get_supercategory(),
            game_category = game_info.get_category(),
            game_subcategory = game_info.get_subcategory(),
            game_name = game_info.get_name(),
            asset_url = asset_url,
            asset_type = asset_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

        # Update metadata entry
        success = collection.UpdateMetadataEntry(
            game_supercategory = game_info.get_supercategory(),
            game_category = game_info.get_category(),
            game_subcategory = game_info.get_subcategory(),
            game_name = game_info.get_name(),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return success

    ############################################################
    # Install
    ############################################################

    # Install game by identifier
    def InstallByIdentifier(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        return False

    # Install by game info
    def InstallByGameInfo(
        self,
        game_info,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Install game
        return self.InstallByIdentifier(
            identifier = self.GetInstallIdentifier(game_info.get_wrapped_value(self.GetKey())),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    ############################################################
    # Launch
    ############################################################

    # Launch by identifier
    def LaunchByIdentifier(
        self,
        identifier,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        return False

    # Launch by game info
    def LaunchByGameInfo(
        self,
        game_info,
        source_type,
        capture_type,
        fullscreen,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check ability to launch
        if not game_info.is_playable():
            return False

        # Launch game
        success = launcher.LaunchGame(
            game_info = game_info,
            source_type = source_type,
            capture_type = capture_type,
            fullscreen = fullscreen,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return success

    ############################################################
    # Download
    ############################################################

    # Download by identifier
    def DownloadByIdentifier(
        self,
        identifier,
        output_dir,
        output_name = None,
        branch = None,
        clean_output = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        return False

    # Download by game info
    def DownloadByGameInfo(
        self,
        game_info,
        output_dir = None,
        skip_existing = False,
        force = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get output dir
        if output_dir:
            output_offset = environment.GetLockerGamingFilesOffset(
                game_supercategory = game_info.get_supercategory(),
                game_category = game_info.get_category(),
                game_subcategory = game_info.get_subcategory(),
                game_name = game_info.get_name())
            output_dir = system.JoinPaths(os.path.realpath(output_dir), output_offset)
        else:
            output_dir = environment.GetLockerGamingFilesDir(
                game_supercategory = game_info.get_supercategory(),
                game_category = game_info.get_category(),
                game_subcategory = game_info.get_subcategory(),
                game_name = game_info.get_name())
        if skip_existing and system.DoesDirectoryContainFiles(output_dir):
            return True

        # Get versions
        local_version, remote_version = self.GetVersions(
            game_info = game_info,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Check if game should be downloaded
        should_download = False
        if force or local_version is None or remote_version is None:
            should_download = True
        elif len(local_version) == 0:
            should_download = True
        elif len(local_version) > 0 and len(remote_version) == 0:
            should_download = True
        else:
            if remote_version.isnumeric() and local_version.isnumeric():
                should_download = int(remote_version) > int(local_version)
            else:
                should_download = remote_version != local_version
        if not should_download:
            return True

        # Download game
        success = self.DownloadByIdentifier(
            identifier = self.GetDownloadIdentifier(game_info.get_wrapped_value(self.GetKey())),
            branch = game_info.get_store_branchid(self.GetKey()),
            output_dir = output_dir,
            output_name = "%s (%s)" % (game_info.get_name(), remote_version),
            clean_output = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return success

    ############################################################
    # Saves
    ############################################################

    # Get save paths
    def GetSavePaths(
        self,
        game_info,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        return []

    # Export saves
    def ExportSaves(
        self,
        game_info,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Create temporary directory
        tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(verbose = verbose)
        if not tmp_dir_success:
            return False

        # Copy save files
        at_least_one_copy = False
        for save_path_entry in self.GetSavePaths(
            game_info = game_info,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure):
            path_full = save_path_entry["full"]
            for path_relative in save_path_entry["relative"]:
                if system.DoesDirectoryContainFiles(path_full):
                    success = system.SmartCopy(
                        src = path_full,
                        dest = system.JoinPaths(tmp_dir_result, path_relative),
                        show_progress = True,
                        skip_existing = True,
                        ignore_symlinks = True,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                    if success:
                        at_least_one_copy = True
        if not at_least_one_copy:
            system.RemoveDirectory(
                dir = tmp_dir_result,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            return True

        # Pack save
        success = saves.PackSave(
            save_category = game_info.get_category(),
            save_subcategory = game_info.get_subcategory(),
            save_name = game_info.get_name(),
            save_dir = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

        # Delete temporary directory
        system.RemoveDirectory(
            dir = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return True

    # Import saves
    def ImportSaves(
        self,
        game_info,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        return False

    ############################################################
    # Archive
    ############################################################

    # Archive
    def Archive(
        self,
        source_dir,
        output_dir,
        output_name,
        excludes = [],
        clean_output = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Create temporary directory
        tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(verbose = verbose)
        if not tmp_dir_success:
            return False

        # Get file paths
        archive_filename = output_name + config.ArchiveFileType.SEVENZIP.cval()
        tmp_archive_file = system.JoinPaths(tmp_dir_result, archive_filename)
        out_archive_file = system.JoinPaths(output_dir, archive_filename)

        # Archive files
        success = archive.CreateArchiveFromFolder(
            archive_file = tmp_archive_file,
            source_dir = source_dir,
            excludes = excludes,
            volume_size = "4092m",
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

        # Clean output
        if clean_output:
            system.RemoveDirectoryContents(
                dir = output_dir,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

        # Move archive
        success = system.SmartMove(
            src = tmp_dir_archive,
            dest = out_archive_file,
            show_progress = True,
            skip_existing = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

        # Delete temporary directory
        system.RemoveDirectory(
            dir = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Check result
        return os.path.exists(out_archive_file)

    ############################################################
    # Backup
    ############################################################

    # Backup
    def Backup(
        self,
        game_info,
        passphrase,
        excludes = [],
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Create temporary directory
        tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(verbose = verbose)
        if not tmp_dir_success:
            return False

        # Download files
        success = self.DownloadByGameInfo(
            game_info = game_info,
            output_dir = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

        # Upload files
        success = collection.UploadGameFiles(
            game_supercategory = game_info.get_supercategory(),
            game_category = game_info.get_category(),
            game_subcategory = game_info.get_subcategory(),
            game_name = game_info.get_name(),
            game_root = tmp_dir_result,
            passphrase = passphrase,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

        # Delete temporary directory
        system.RemoveDirectory(
            dir = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Should be successful
        return True

    ############################################################
