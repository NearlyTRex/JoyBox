#!/usr/bin/env python3

# Imports
import os, os.path
import sys
import argparse

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import environment
import gameinfo
import stores
import setup

# Parse arguments
parser = argparse.ArgumentParser(description="Manage store games.")
parser.add_argument("-i", "--input_path", type=str, default=".", help="Input path")
parser.add_argument("-t", "--store_type",
    choices=config.StoreType.values(),
    default=config.StoreType.STEAM,
    type=config.StoreType,
    action=config.EnumArgparseAction,
    help="Store type"
)
parser.add_argument("-a", "--store_action",
    choices=config.StoreActionType.values(),
    default=config.StoreActionType.LOGIN,
    type=config.StoreActionType,
    action=config.EnumArgparseAction,
    help="Store action type"
)
parser.add_argument("-e", "--asset_type",
    choices=config.AssetType.values(),
    type=config.AssetType,
    action=config.EnumArgparseAction,
    help="Asset type"
)
parser.add_argument("-s", "--skip_existing", action="store_true", help="Skip existing entries")
parser.add_argument("-f", "--force", action="store_true", help="Always run action")
parser.add_argument("-k", "--keys", type=str, help="Keys to use (comma delimited)")
parser.add_argument("-o", "--output_dir", type=str, default=".", help="Output directory")
parser.add_argument("-m", "--load_manifest", action="store_true", help="Load manifest")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
parser.add_argument("-p", "--pretend_run", action="store_true", help="Do a pretend run with no permanent changes")
parser.add_argument("-x", "--exit_on_failure", action="store_true", help="Enable exit on failure mode")
args, unknown = parser.parse_known_args()

# Get store
store_obj = stores.GetStoreByType(args.store_type)
if not store_obj:
    system.LogErrorAndQuit("Invalid store")

# Get input path
input_path = None
if system.IsPathValid(args.input_path):
    input_path = os.path.realpath(args.input_path)
    if not os.path.exists(input_path):
        system.LogErrorAndQuit("Path '%s' does not exist" % args.input_path)
if not input_path:
    input_path = environment.GetJsonRomMetadataDir(
        game_category = store_obj.GetCategory(),
        game_subcategory = store_obj.GetSubcategory())

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Load manifest
    if args.load_manifest:
        store_obj.LoadManifest(
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Login
    if args.store_action == config.StoreActionType.LOGIN:
        store_obj.Login(
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Display purchases
    elif args.store_action == config.StoreActionType.DISPLAY_PURCHASES:
        store_obj.DisplayPurchases(
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Import purchases
    elif args.store_action == config.StoreActionType.IMPORT_PURCHASES:
        store_obj.ImportPurchases(
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

    # Install game
    elif args.store_action == config.StoreActionType.INSTALL_GAME:
        for json_file in system.BuildFileListByExtensions(input_path, extensions = [".json"]):
            game_info = gameinfo.GameInfo(
                json_file = json_file,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
            if game_info and game_info.is_valid():
                success = store_obj.InstallByGameInfo(
                    game_info = game_info,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)
                if not success:
                    system.LogErrorAndQuit("Install of '%s' failed!" % json_file)

    # Launch game
    elif args.store_action == config.StoreActionType.LAUNCH_GAME:
        for json_file in system.BuildFileListByExtensions(input_path, extensions = [".json"]):
            game_info = gameinfo.GameInfo(
                json_file = json_file,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
            if game_info and game_info.is_valid():
                store_obj.LaunchByGameInfo(
                    game_info = game_info,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)
            break

    # Download game
    elif args.store_action == config.StoreActionType.DOWNLOAD_GAME:
        for json_file in system.BuildFileListByExtensions(input_path, extensions = [".json"]):
            game_info = gameinfo.GameInfo(
                json_file = json_file,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
            if game_info and game_info.is_valid():
                success = store_obj.DownloadByGameInfo(
                    game_info = game_info,
                    output_dir = args.output_dir,
                    skip_existing = args.skip_existing,
                    force = args.force,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)
                if not success:
                    system.LogErrorAndQuit("Download of '%s' failed!" % json_file)

    # Download asset
    elif args.store_action == config.StoreActionType.DOWNLOAD_ASSET:
        for json_file in system.BuildFileListByExtensions(input_path, extensions = [".json"]):
            game_info = gameinfo.GameInfo(
                json_file = json_file,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
            if game_info and game_info.is_valid():
                success = store_obj.DownloadAsset(
                    game_info = game_info,
                    asset_type = args.asset_type,
                    force = args.force,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)
                if not success:
                    system.LogErrorAndQuit("Download of asset for '%s' failed!" % json_file)

    # Update json
    elif args.store_action == config.StoreActionType.UPDATE_JSON:
        for json_file in system.BuildFileListByExtensions(input_path, extensions = [".json"]):
            game_info = gameinfo.GameInfo(
                json_file = json_file,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
            if game_info and game_info.is_valid():
                success = store_obj.UpdateJson(
                    game_info = game_info,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)
                if not success:
                    system.LogErrorAndQuit("Update of '%s' failed!" % json_file)

    # Update metadata
    elif args.store_action == config.StoreActionType.UPDATE_METADATA:
        for json_file in system.BuildFileListByExtensions(input_path, extensions = [".json"]):
            game_info = gameinfo.GameInfo(
                json_file = json_file,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
            if game_info and game_info.is_valid():
                success = store_obj.UpdateMetadata(
                    game_info = game_info,
                    keys = args.keys.split(",") if args.keys else [],
                    force = args.force,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)
                if not success:
                    system.LogErrorAndQuit("Update of '%s' failed!" % json_file)

    # Check versions
    elif args.store_action == config.StoreActionType.CHECK_VERSIONS:
        for json_file in system.BuildFileListByExtensions(input_path, extensions = [".json"]):
            game_info = gameinfo.GameInfo(
                json_file = json_file,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            if game_info and game_info.is_valid():
                local_version, remote_version = store_obj.GetVersions(
                    game_info = game_info,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)
                if local_version and remote_version:
                    if local_version != remote_version:
                        system.LogWarning("Game '%s' is out of date! Local = '%s', remote = '%s'" % (json_file, local_version, remote_version))

    # Export saves
    elif args.store_action == config.StoreActionType.EXPORT_SAVES:
        for json_file in system.BuildFileListByExtensions(input_path, extensions = [".json"]):
            game_info = gameinfo.GameInfo(
                json_file = json_file,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
            if game_info and game_info.is_valid():
                success = store_obj.ExportSave(
                    game_info = game_info,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)
                if not success:
                    system.LogErrorAndQuit("Export of '%s' failed!" % json_file)

    # Import saves
    elif args.store_action == config.StoreActionType.IMPORT_SAVES:
        for json_file in system.BuildFileListByExtensions(input_path, extensions = [".json"]):
            game_info = gameinfo.GameInfo(
                json_file = json_file,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
            if game_info and game_info.is_valid():
                success = store_obj.ImportSave(
                    game_info = game_info,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)
                if not success:
                    system.LogErrorAndQuit("Import of '%s' failed!" % json_file)

# Start
main()
