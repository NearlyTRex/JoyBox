# Imports
import os
import os.path
from joybox import system
from joybox import google
from joybox import arguments
from joybox import setup
from joybox import logger

# Build the argument parser
def build_parser():
    parser = arguments.ArgumentParser(command = "download_youtube_videos")
    parser.add_string_argument(args = "youtube_url", description = "URL of the video, playlist or channel to download")
    parser.add_group("Download")
    parser.add_boolean_argument(args = ("-a", "--audio_only"), description = "Extract the audio as MP3 instead of downloading an MP4 video")
    parser.add_group("Output")
    parser.add_output_path_argument(args = ("-o", "--output_file"), description = "yt-dlp output template or file name, relative to `-d`; `<upload date> - <title>.<ext>` when omitted")
    parser.add_output_path_argument(args = ("-d", "--output_dir"), default = os.path.realpath("."), description = "Directory to download into; the current directory when omitted")
    parser.add_group("Behavior")
    parser.add_input_path_argument(args = ("-r", "--download_archive"), description = "yt-dlp download archive file; videos listed in it are skipped and new downloads are added to it")
    parser.add_string_argument(args = ("-c", "--cookie_source"), default = "firefox", description = "Browser to read cookies from (passed to yt-dlp as `--cookies-from-browser`), or the path of a cookies file (passed as `--cookies`)")
    parser.add_boolean_argument(args = ("-s", "--sanitize_filenames"), description = "After downloading, rename files in the output directory to remove characters that are invalid in paths")
    parser.add_common_arguments()
    return parser

# Download a video, playlist or channel URL with yt-dlp as MP4, or as MP3 with the audio flag
def main():

    # Parse arguments
    parser = build_parser()
    args, _ = parser.parse_known_args()

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Download videos
    google.download_video(
        video_url = args.youtube_url,
        audio_only = args.audio_only,
        output_file = args.output_file,
        output_dir = args.output_dir,
        download_archive = args.download_archive,
        cookie_source = args.cookie_source,
        sanitize_filenames = args.sanitize_filenames,
        verbose = args.verbose,
        pretend_run = args.pretend_run,
        exit_on_failure = args.exit_on_failure)

# Run through the shared error handling
def run():
    system.run_main(main)

# Start
if __name__ == "__main__":
    run()
