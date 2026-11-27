# Imports
from joybox import system
from joybox import arguments
from joybox import setup
from joybox import logger
from joybox import fileops
from joybox import paths

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "make_folders")
    parser.add_input_path_argument(description = "Directory whose top-level files are sorted into folders; it must exist")
    parser.add_string_argument(args = ("-f", "--file_types"), default = ".iso,.chd,.rvz,.zip,.7z,.rar,.pkg", description = "Comma-separated filename endings to match, with the leading dot")
    parser.add_common_arguments()
    return parser

# Move each file with a given extension directly inside the input dir into a folder named after it
def main():

    # Parse arguments
    parser = build_parser()
    args, _ = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Get input path
    input_path = parser.get_input_path()

    # Make folders from file types
    for obj in paths.get_directory_contents(input_path):
        obj_path = paths.join_paths(input_path, obj)
        if paths.is_path_file(obj_path):
            if obj.endswith(tuple(args.file_types.split(","))):
                selected_file = obj_path
                selected_file_basename = paths.get_filename_basename(selected_file)
                new_folder = paths.join_paths(input_path, selected_file_basename)
                new_file = paths.join_paths(input_path, selected_file_basename, obj)
                fileops.make_directory(
                    src = new_folder,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)
                fileops.move_file_or_directory(
                    src = selected_file,
                    dest = new_file,
                    verbose = args.verbose,
                    pretend_run = args.pretend_run,
                    exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
