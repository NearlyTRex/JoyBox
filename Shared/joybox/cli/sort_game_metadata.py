# Imports
from joybox import environment
from joybox import metadata
from joybox import system
from joybox import arguments
from joybox import setup
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "sort_game_metadata")
    parser.add_common_arguments()
    return parser

# After a preview, rewrite every Pegasus metadata file found under the metadata repository in sorted order
def main():

    # Parse arguments, check requirements and set up logging
    parser = build_parser()
    args = setup.start_command(parser)

    # Get metadata dir
    metadata_dir = environment.get_game_pegasus_metadata_root_dir()

    # Find all metadata files
    metadata_files = metadata.find_game_metadata_files(metadata_dir)

    # Show preview
    details = [
        "Metadata dir: %s" % metadata_dir,
        "Files to sort: %d" % len(metadata_files)
    ]
    if not prompts.confirm_preview(args.no_preview, "Sort game metadata", details):
        return

    # Sort each metadata file
    metadata.sort_game_metadata_files(
        metadata_files,
        verbose = args.verbose,
        pretend_run = args.pretend_run)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
