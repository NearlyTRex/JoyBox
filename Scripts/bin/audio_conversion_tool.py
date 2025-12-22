#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import audible
import arguments
import setup
import logger
import paths

# Parse arguments
parser = arguments.ArgumentParser(description = "Audio conversion tool for converting between audio formats.")
parser.add_enum_argument(
    args = ("-a", "--action"),
    arg_type = config.AudioConversionAction,
    default = config.AudioConversionAction.AAX_TO_M4A,
    description = "Conversion action to perform")
parser.add_input_path_argument(required = True)
parser.add_output_path_argument()
parser.add_string_argument(
    args = ("-k", "--activation_bytes"),
    description = "Audible activation bytes (8 hex characters)")
parser.add_string_argument(
    args = ("-f", "--authcode_file"),
    description = "Path to file containing activation bytes")
parser.add_boolean_argument(
    args = ("-r", "--recursive"),
    description = "Process directories recursively")
parser.add_boolean_argument(
    args = ("--overwrite",),
    description = "Overwrite existing output files")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Setup logging
    logger.setup_logging()

    # Get input path
    input_path = parser.get_input_path()

    # Get output path (optional, don't validate existence)
    output_path = args.output_path

    # Execute action
    if args.action == config.AudioConversionAction.AAX_TO_M4A:

        # Check if input is a directory or file
        if paths.is_path_directory(input_path):
            return audible.DecryptAAXDirectory(
                input_dir = input_path,
                output_dir = output_path,
                activation_bytes = args.activation_bytes,
                authcode_file = args.authcode_file,
                recursive = args.recursive,
                overwrite = args.overwrite,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
        elif paths.is_path_file(input_path):
            return audible.DecryptAAXToM4A(
                input_file = input_path,
                output_file = output_path,
                activation_bytes = args.activation_bytes,
                authcode_file = args.authcode_file,
                overwrite = args.overwrite,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
    else:
        logger.log_error(f"Unknown action: {args.action}")
        return False

# Main
if __name__ == "__main__":
    system.RunMain(main)
