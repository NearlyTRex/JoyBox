#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.config as config
import joybox.system as system
import joybox.audible as audible
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger
import joybox.paths as paths

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Convert Audible AAX and AA audiobooks to M4A.",
    details = (
        "The only action is `AaxToM4a`. It removes Audible's DRM with FFmpeg's\n"
        "`-activation_bytes` and copies the streams unchanged (`-c copy`), so there is no\n"
        "re-encoding and the chapters are kept.\n"
        "\n"
        "The input may be one `.aax`/`.aa` file or a directory. For a file, the output is `-o`,\n"
        "or the input path with an `.m4a` extension. For a directory, every `.aax`/`.aa` file\n"
        "in it (and in its sub-directories with `-r`) is converted into `-o`, or into the input\n"
        "directory itself, as `<name>.m4a`.\n"
        "\n"
        "Without `-k`, the activation bytes are taken from the first of these that holds an\n"
        "8-hex-digit value: `audible_activation_bytes` in `[UserData.Audible]` of the\n"
        "configuration, the `-f` file, the `AUDIBLE_ACTIVATION_BYTES` environment variable, and\n"
        "`~/.audible_authcode`."),
    examples = [
        ("Convert one book, finding the activation bytes automatically", "audio_conversion_tool -i \"/path/to/book.aax\""),
        ("Convert one book to a chosen file with explicit activation bytes", "audio_conversion_tool -i \"/path/to/book.aax\" -o \"/path/to/book.m4a\" -k 1a2b3c4d"),
        ("Convert every book in a directory", "audio_conversion_tool -i \"/path/to/audiobooks\""),
        ("Convert a directory tree, replacing earlier conversions", "audio_conversion_tool -i \"/path/to/audiobooks\" -r --overwrite"),
        ("Read the activation bytes from a file", "audio_conversion_tool -i \"/path/to/book.aax\" -f \"/path/to/authcode.txt\""),
        ("List what would be converted without running FFmpeg", "audio_conversion_tool -i \"/path/to/audiobooks\" -r -p -v"),
    ],
    notes = [
        "Without `--overwrite`, a book whose output already exists is skipped and counted as a success.",
        "Needs FFmpeg.",
    ],
    see_also = ["audio_metadata_tool", "tag_audio_files", "generate_playlist"],
    section = "Audio & Video")
parser.add_group("Conversion")
parser.add_enum_argument(
    args = ("-a", "--action"),
    arg_type = config.AudioConversionAction,
    default = config.AudioConversionAction.AAX_TO_M4A,
    description = "Conversion to run")
parser.add_input_path_argument(required = True, description = "`.aax`/`.aa` file, or directory of them, to convert; must exist")
parser.add_output_path_argument(description = "Output `.m4a` file for a file input, or output directory for a directory input; next to the input when omitted")
parser.add_group("Decryption")
parser.add_string_argument(
    args = ("-k", "--activation_bytes"),
    description = "Audible activation bytes, 8 hex digits; skips the automatic lookup")
parser.add_string_argument(
    args = ("-f", "--authcode_file"),
    description = "File containing the activation bytes, used when the configuration has none")
parser.add_group("Behavior")
parser.add_boolean_argument(
    args = ("-r", "--recursive"),
    description = "For a directory input, also convert books in its sub-directories")
parser.add_boolean_argument(
    args = ("--overwrite",),
    description = "Replace existing output files instead of skipping those books")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

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
            return audible.decrypt_aax_directory(
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
            return audible.decrypt_aax_to_m4a(
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
    system.run_main(main)
