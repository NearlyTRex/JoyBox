# Imports
from joybox import config
from joybox import system
from joybox import metadata
from joybox import environment
from joybox import arguments
from joybox import setup
from joybox import logger
from joybox import paths
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "clean_game_metadata_files")
    parser.add_common_arguments()
    return parser

# After a preview, rewrite the Pegasus metadata file of each known category and subcategory in sorted order
def main():

    # Parse arguments
    parser = build_parser()
    args, _ = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Collect metadata files to process
    metadata_files_to_process = []
    for game_category in config.Category.members():
        for game_subcategory in config.subcategory_map[game_category]:

            # Get metadata file
            metadata_file = environment.get_game_metadata_file(game_category, game_subcategory)
            if not paths.is_path_file(metadata_file):
                continue
            metadata_files_to_process.append((game_category, game_subcategory, metadata_file))

    # Show preview
    if not args.no_preview:
        details = [metadata_file for _, _, metadata_file in metadata_files_to_process]
        if not prompts.prompt_for_preview("Clean game metadata files (sort entries)", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Sort metadata files
    for game_category, game_subcategory, metadata_file in metadata_files_to_process:
        logger.log_info("Sorting metadata files for %s - %s..." % (game_category, game_subcategory))
        metadata_obj = metadata.Metadata()
        metadata_obj.import_from_metadata_file(metadata_file)
        metadata_obj.export_to_metadata_file(metadata_file)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
