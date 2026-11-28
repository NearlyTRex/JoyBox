# Imports
from joybox import system
from joybox import archive
from joybox import arguments
from joybox import setup
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "rezip_files")
    parser.add_input_path_argument(description = "A `.zip` file, or a directory searched recursively for them; must exist")
    parser.add_common_arguments()
    return parser

# After a preview, rebuild each zip under the input in place with fixed, reproducible 7-Zip settings
def main():

    # Parse arguments, check requirements and set up logging
    parser = build_parser()
    args = setup.start_command(parser)

    # Get input path
    input_path = parser.get_input_path()

    # Show preview
    details = ["Path: %s" % input_path]
    if not prompts.confirm_preview(args.no_preview, "Rezip files deterministically", details):
        return

    # Rezip zip files
    archive.rezip_archives(
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
