# Imports
from joybox import system
from joybox import playstation
from joybox import arguments
from joybox import setup
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "psn_rom_tool")
    parser.add_input_path_argument(description = "A PSN file, or a directory searched recursively for `.pkg`, `.rap`, `.work.bin` and `.fake.rif` files; must exist")
    parser.add_boolean_argument(args = ("-r", "--rename"), description = "Rename each file to `<content id>` plus its original extension")
    parser.add_common_arguments()
    return parser

# After a preview, rename the PSN packages and license files under the input to their content IDs
def main():

    # Parse arguments, check requirements and set up logging
    parser = build_parser()
    args = setup.start_command(parser)

    # Get input path
    input_path = parser.get_input_path()

    # Show preview
    details = [
        "Path: %s" % input_path,
        "Action: Rename PSN files"
    ]
    if not prompts.confirm_preview(args.no_preview, "PSN ROM tool", details):
        return

    # Rename psn files
    if args.rename:
        playstation.rename_psn_files(
            input_path = input_path,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
