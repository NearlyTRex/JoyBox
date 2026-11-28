# Imports
from joybox import system
from joybox import arguments
from joybox import setup
from joybox import fileops
from joybox import prompts

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "sanitize_filenames")
    parser.add_input_path_argument(description = "Directory whose top-level files are renamed; it must exist")
    parser.add_common_arguments()
    return parser

# After a preview, rename each file directly inside the input dir to a plain ASCII name safe on every filesystem
def main():

    # Parse arguments, check requirements and set up logging
    parser = build_parser()
    args = setup.start_command(parser)

    # Get input path
    input_path = parser.get_input_path()

    # Show preview
    details = ["Path: %s" % input_path]
    if not prompts.confirm_preview(args.no_preview, "Sanitize filenames", details):
        return

    # Sanitize filenames
    fileops.sanitize_filenames(
        path = input_path,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
