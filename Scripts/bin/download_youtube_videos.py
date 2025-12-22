#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
sys.path.append(lib_folder)
import config
import system
import metadata
import google
import arguments
import setup
import logger

# Parse arguments
parser = arguments.ArgumentParser(description = "Download youtube videos.")
parser.add_string_argument(args = "youtube_url", description = "YouTube url")
parser.add_boolean_argument(args = ("-a", "--audio_only"), description = "Audio only")
parser.add_output_path_argument(args = ("-o", "--output_file"), description = "Output file")
parser.add_output_path_argument(args = ("-d", "--output_dir"), default = os.path.realpath("."), description = "Output dir")
parser.add_input_path_argument(args = ("-r", "--download_archive"), description = "Download archive")
parser.add_string_argument(args = ("-c", "--cookie_source"), default = "firefox", description = "Cookie source")
parser.add_boolean_argument(args = ("-s", "--sanitize_filenames"), description = "Sanitize filenames")
parser.add_common_arguments()
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.CheckRequirements()

    # Setup logging
    logger.setup_logging()

    # Download videos
    google.DownloadVideo(
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

# Start
if __name__ == "__main__":
    system.RunMain(main)
