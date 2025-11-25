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

# Parse arguments
parser = arguments.ArgumentParser(description = "Audio conversion tool for converting between audio formats.")
parser.add_enum_argument(
    args = ("-a", "--action"),
    arg_type = config.AudioConversionAction,
    default = config.AudioConversionAction.AAX_TO_M4A,
    description = "Conversion action to perform")
parser.add_input_path_argument(required = True)
parser.add_string_argument(
    args = ("-o", "--output_path"),
    description = "Output file or directory path")
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

    # Execute action
    if args.action == config.AudioConversionAction.AAX_TO_M4A:

        # Check if input is a directory or file
        if system.IsPathDirectory(args.input_path):
            return audible.DecryptAAXDirectory(
                input_dir = args.input_path,
                output_dir = args.output_path,
                activation_bytes = args.activation_bytes,
                authcode_file = args.authcode_file,
                recursive = args.recursive,
                overwrite = args.overwrite,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
        elif system.IsPathFile(args.input_path):
            return audible.DecryptAAXToM4A(
                input_file = args.input_path,
                output_file = args.output_path,
                activation_bytes = args.activation_bytes,
                authcode_file = args.authcode_file,
                overwrite = args.overwrite,
                verbose = args.verbose,
                pretend_run = args.pretend_run,
                exit_on_failure = args.exit_on_failure)
        else:
            system.LogError(f"Input path does not exist: {args.input_path}")
            return False
    else:
        system.LogError(f"Unknown action: {args.action}")
        return False

# Main
if __name__ == "__main__":
    system.RunMain(main)
