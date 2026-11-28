# Imports
from joybox import config
from joybox import system
from joybox import audible
from joybox import arguments
from joybox import setup

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "audio_conversion_tool")
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
    return parser

# Strip the DRM from an Audible AAX/AA file, or every one in a directory, into M4A with FFmpeg, copying the streams unchanged
def main():

    # Parse arguments, check requirements and set up logging
    parser = build_parser()
    args = setup.start_command(parser)

    # Convert a directory or a single file; AaxToM4a is the only action
    return audible.decrypt_aax_path(
        input_path = parser.get_input_path(),
        output_path = args.output_path,
        activation_bytes = args.activation_bytes,
        authcode_file = args.authcode_file,
        recursive = args.recursive,
        overwrite = args.overwrite,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
