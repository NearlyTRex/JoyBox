# Imports
import sys
from joybox import config
from joybox import system
from joybox import audio
from joybox import arguments
from joybox import setup
from joybox import logger

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "download_audio_files")
    parser.add_group("Selection")
    parser.add_enum_argument(
        args = ("-g", "--genre_type"),
        arg_type = config.AudioGenreType,
        description = "Genre whose channels to download; only `Story` and `ASMR` do anything")
    parser.add_string_argument(args = ("-c", "--cookie_source"), default = "firefox", description = "Browser to read cookies from (passed to yt-dlp as `--cookies-from-browser`), or the path of a cookies file (passed as `--cookies`)")
    parser.add_string_argument(args = ("-n", "--channel_name"), default = None, description = "Download only channels whose configured name matches, case-insensitively: an exact match if there is one, otherwise every name containing it. No match stops the run and lists the names")
    parser.add_boolean_argument(args = ("--oldest_first",), description = "Download each channel's new videos oldest first, overriding `audio_download_oldest_first`")
    parser.add_boolean_argument(args = ("--newest_first",), description = "Download each channel's new videos newest first, overriding `audio_download_oldest_first`; wins if both order flags are given")
    parser.add_group("Output")
    parser.add_enum_argument(
        args = ("-l", "--locker_type"),
        arg_type = config.LockerType,
        default = config.LockerType.ALL,
        description = "Locker to copy the audio to; `All` means every configured locker")
    parser.add_output_path_argument(description = "Directory to keep each channel's downloads in (`<output_path>/<channel>`) so an interrupted run can resume; a temporary directory per batch when omitted")
    parser.add_common_arguments()
    return parser

# Download new videos from the Story or ASMR genre's configured channels as MP3 and back them up to the locker
def main():

    # Parse arguments
    parser = build_parser()
    args, _ = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Download the genre's audio
    success = audio.download_genre_audio_files(
        genre_type = args.genre_type,
        channel_name = args.channel_name,
        oldest_first = args.oldest_first,
        newest_first = args.newest_first,
        cookie_source = args.cookie_source,
        locker_type = args.locker_type,
        output_path = args.output_path,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)
    if not success:
        sys.exit(1)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
