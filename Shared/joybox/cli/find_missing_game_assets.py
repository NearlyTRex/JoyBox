# Imports
from joybox import environment
from joybox import metadata
from joybox import system
from joybox import arguments
from joybox import setup
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "find_missing_game_assets")
    parser.add_common_arguments()
    return parser

# After a preview, report the Pegasus entries missing each asset type and the asset files no entry uses, writing each list to a file
def main():

    # Parse arguments, check requirements and set up logging
    parser = build_parser()
    args = setup.start_command(parser)

    # Get search info
    assets_dir = environment.get_locker_gaming_assets_root_dir()
    metadata_dir = environment.get_game_pegasus_metadata_root_dir()

    # Show preview
    details = [
        "Assets dir: %s" % assets_dir,
        "Metadata dir: %s" % metadata_dir
    ]
    if not prompts.confirm_preview(args.no_preview, "Find missing game assets", details):
        return

    # Report missing and extra assets
    metadata.report_missing_game_assets(
        assets_dir = assets_dir,
        metadata_dir = metadata_dir,
        verbose = args.verbose,
        pretend_run = args.pretend_run)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
