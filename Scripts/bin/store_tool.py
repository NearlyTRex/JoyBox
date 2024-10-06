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
    choices=config.store_types,
    default=config.store_type_steam,
    help="Store type"
)
parser.add_argument("-a", "--store_action",
    choices=config.store_action_types,
    default=config.store_action_type_login,
    help="Store action"
)
parser.add_argument("-s", "--skip_existing", action="store_true", help="Skip existing entries")
parser.add_argument("-f", "--force", action="store_true", help="Always run action")
parser.add_argument("-o", "--output_dir", type=str, default=".", help="Output directory")
parser.add_argument("-m", "--load_manifest", action="store_true", help="Load manifest")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
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
            exit_on_failure = args.exit_on_failure)

    # Login
    if args.store_action == config.store_action_type_login:
        store_obj.Login(
            verbose = args.verbose,
            exit_on_failure = args.exit_on_failure)

    # Display purchases
    elif args.store_action == config.store_action_type_display_purchases:
        store_obj.DisplayPurchases(
            verbose = args.verbose,
            exit_on_failure = args.exit_on_failure)

    # Import purchases
    elif args.store_action == config.store_action_type_import_purchases:
        store_obj.ImportPurchases(
            verbose = args.verbose,
            exit_on_failure = args.exit_on_failure)

    # Install game
    elif args.store_action == config.store_action_type_install_game:
        for json_file in system.BuildFileListByExtensions(input_path, extensions = [".json"]):
            game_info = gameinfo.GameInfo(
                json_file = json_file,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)
            success = store_obj.InstallByGameInfo(
                game_info = game_info,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)
            if not success:
                system.LogErrorAndQuit("Install of '%s' failed!" % game_info.get_name())

    # Launch game
    elif args.store_action == config.store_action_type_launch_game:
        for json_file in system.BuildFileListByExtensions(input_path, extensions = [".json"]):
            game_info = gameinfo.GameInfo(
                json_file = json_file,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)
            store_obj.LaunchByGameInfo(
                game_info = game_info,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)
            break

    # Download game
    elif args.store_action == config.store_action_type_download_game:
        for json_file in system.BuildFileListByExtensions(input_path, extensions = [".json"]):
            game_info = gameinfo.GameInfo(
                json_file = json_file,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)
            success = store_obj.DownloadByGameInfo(
                game_info = game_info,
                output_dir = args.output_dir,
                skip_existing = args.skip_existing,
                force = args.force,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)
            if not success:
                system.LogErrorAndQuit("Install of '%s' failed!" % game_info.get_name())

    # Update json
    elif args.store_action == config.store_action_type_update_json:
        for json_file in system.BuildFileListByExtensions(input_path, extensions = [".json"]):
            game_info = gameinfo.GameInfo(
                json_file = json_file,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)
            success = store_obj.UpdateJson(
                game_info = game_info,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)
            if not success:
                system.LogErrorAndQuit("Update of '%s' failed!" % game_info.get_name())

    # Check versions
    elif args.store_action == config.store_action_type_check_versions:
        for json_file in system.BuildFileListByExtensions(input_path, extensions = [".json"]):
            game_info = gameinfo.GameInfo(
                json_file = json_file,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            local_version, remote_version = store_obj.GetVersions(
                game_info = game_info,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)
            if local_version and remote_version:
                if local_version != remote_version:
                    system.LogWarning("Game '%s' is out of date! Local = '%s', remote = '%s'" % (json_file, local_version, remote_version))

    # Export saves
    elif args.store_action == config.store_action_type_export_saves:
        for json_file in system.BuildFileListByExtensions(input_path, extensions = [".json"]):
            game_info = gameinfo.GameInfo(
                json_file = json_file,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)
            success = store_obj.ExportSave(
                game_info = game_info,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)
            if not success:
                system.LogErrorAndQuit("Export of '%s' failed!" % game_info.get_name())

    # Import saves
    elif args.store_action == config.store_action_type_import_saves:
        for json_file in system.BuildFileListByExtensions(input_path, extensions = [".json"]):
            game_info = gameinfo.GameInfo(
                json_file = json_file,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)
            success = store_obj.ImportSave(
                game_info = game_info,
                verbose = args.verbose,
                exit_on_failure = args.exit_on_failure)
            if not success:
                system.LogErrorAndQuit("Import of '%s' failed!" % game_info.get_name())

# Start
main()
