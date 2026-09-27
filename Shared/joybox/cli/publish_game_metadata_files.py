# Imports
import joybox.system as system
import joybox.environment as environment
import joybox.collection as collection
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.prompts as prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(
        description = "Render the Pegasus metadata as one browsable HTML table per category.",
        details = (
            "For each category, reads the metadata file of every subcategory that has one and\n"
            "writes `Published/<Category>.html` in the game metadata repository, for example\n"
            "`Nintendo.html`. Each game gets a table row with a per-platform number, its platform,\n"
            "name, player count and co-op flag, and search links to GameFAQs and MobyGames.\n"
            "\n"
            "Only `Roms` metadata is published. Existing pages are overwritten."),
        examples = [
            ("Publish every category", "publish_game_metadata_files"),
            ("Publish without the confirmation prompt", "publish_game_metadata_files --no-preview"),
            ("Dry run", "publish_game_metadata_files -p -v"),
        ],
        notes = [
            "There are no selection options; every category is published.",
            "`scan_game_files` runs this same step at the end of its pipeline.",
        ],
        see_also = ["build_game_metadata_files", "sort_game_metadata", "scan_game_files"],
        section = "Game Collection")
    parser.add_common_arguments()
    return parser

# Main
def main():

    # Parse arguments
    parser = build_parser()
    args, unknown = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Show preview
    if not args.no_preview:
        publish_dir = environment.get_game_published_metadata_root_dir()
        if not prompts.prompt_for_preview("Publish game metadata files to HTML", [publish_dir]):
            logger.log_warning("Operation cancelled by user")
            return

    # Publish game metadata files
    logger.log_info("Publishing game metadata files ...")
    success = collection.publish_all_game_metadata_entries(
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if not success:
        logger.log_error("Publishing metadata files failed", quit_program = True)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
