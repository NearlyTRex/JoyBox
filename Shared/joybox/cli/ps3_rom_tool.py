# Imports
from joybox import system
from joybox import playstation
from joybox import arguments
from joybox import setup
from joybox import paths
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "ps3_rom_tool")
    parser.add_input_path_argument(description = "A PS3 `.chd` file, or a directory searched recursively for them; must exist")
    parser.add_boolean_argument(args = ("-e", "--verify_chd"), description = "Verify each CHD by decrypting and unpacking it with its `.dkey` file; without it nothing is done")
    parser.add_common_arguments()
    return parser

# After a preview, check each PS3 disc CHD under the input decrypts with its disc key and extracts
def main():

    # Parse arguments, check requirements and set up logging
    parser = build_parser()
    args = setup.start_command(parser)

    # Get input path
    input_path = parser.get_input_path()

    # Show preview
    details = [
        "Path: %s" % input_path,
        "Action: Verify CHD"
    ]
    if not prompts.confirm_preview(args.no_preview, "PS3 ROM tool", details):
        return

    # Find rom files
    for file in paths.build_file_list_by_extensions(input_path, extensions = [".chd"]):

        # Verify chd
        if args.verify_chd:
            playstation.verify_ps3_chd(
                chd_file = file,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
