#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import environment
import collection
import gameinfo
import arguments
import setup

# Parse arguments
parser = arguments.ArgumentParser(description = "Upload game files.")
parser.add_input_path_argument()
parser.add_game_supercategory_argument()
parser.add_game_category_argument()
parser.add_game_subcategory_argument()
parser.add_game_name_argument()
parser.add_enum_argument(
    args = ("-l", "--source_type"),
    arg_type = config.SourceType,
    default = config.SourceType.LOCAL,
    description = "Source type")
parser.add_enum_argument(
    args = ("-m", "--generation_mode"),
    arg_type = config.GenerationModeType,
    default = config.GenerationModeType.STANDARD,
    description = "Generation mode")
parser.add_enum_argument(
    args = ("-t", "--locker_type"),
    arg_type = config.LockerType,
    description = "Locker type")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Get custom input path if provided
    custom_input_path = parser.get_path("input_path")

    # Collect games to process
    games_to_process = []
    for game_info in gameinfo.IterateSelectedGameInfos(
        parser = parser,
        generation_mode = args.generation_mode,
        source_type = args.source_type,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure):
        game_root = custom_input_path or environment.GetLockerGamingFilesDir(
            game_info.get_supercategory(),
            game_info.get_category(),
            game_info.get_subcategory(),
            game_info.get_name(),
            args.source_type)
        games_to_process.append((game_info, game_root))

    # Show preview
    if not args.no_preview:
        details = [game_root for _, game_root in games_to_process]
        if not system.PromptForPreview("Upload game files (encrypt and upload to %s)" % args.locker_type, details):
            system.LogWarning("Operation cancelled by user")
            return

    # Upload game files
    for game_info, game_root in games_to_process:
        success = collection.UploadGameFiles(
            game_info = game_info,
            game_root = game_root,
            locker_type = args.locker_type,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if not success:
            system.LogError(
                message = "Upload of game files failed!",
                game_supercategory = game_info.get_supercategory(),
                game_category = game_info.get_category(),
                game_subcategory = game_info.get_subcategory(),
                game_name = game_info.get_name(),
                quit_program = True)

# Start
if __name__ == "__main__":
    system.RunMain(main)
