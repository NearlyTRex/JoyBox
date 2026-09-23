#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.config as config
import joybox.system as system
import joybox.metadata as metadata
import joybox.google as google
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Download a video, playlist or channel with yt-dlp as MP4 or MP3.",
    details = (
        "Hands the URL to yt-dlp. Videos are converted to MP4; with `-a` the audio is extracted\n"
        "to MP3 instead, with the thumbnail and metadata embedded. Files are written to `-d`,\n"
        "named `<upload date> - <title>.<ext>` unless `-o` gives a yt-dlp output template.\n"
        "\n"
        "yt-dlp resumes partly downloaded files, pauses 3-5 seconds between videos, and uses\n"
        "Deno (from `~/.deno/bin/deno` or `PATH`) for YouTube's download challenge when it is\n"
        "installed. Any site yt-dlp supports works, not only YouTube."),
    examples = [
        ("Download a video into the current directory", "download_youtube_videos \"https://www.youtube.com/watch?v=VIDEO_ID\""),
        ("Download a playlist's audio as MP3 into a folder", "download_youtube_videos \"https://www.youtube.com/playlist?list=PLAYLIST_ID\" -a -d /path/to/music"),
        ("Download only videos not fetched before, recording them in an archive", "download_youtube_videos \"https://www.youtube.com/@channel\" -d /path/to/videos -r /path/to/archive.txt"),
        ("Download with a chosen file name", "download_youtube_videos \"https://www.youtube.com/watch?v=VIDEO_ID\" -o \"My Video.%(ext)s\""),
        ("Use a cookies file and clean up the file names afterwards", "download_youtube_videos \"https://www.youtube.com/watch?v=VIDEO_ID\" -c /path/to/cookies.txt -s"),
        ("Pretend run, without downloading anything", "download_youtube_videos \"https://www.youtube.com/watch?v=VIDEO_ID\" -p -v"),
    ],
    notes = [
        "`-s` renames every `.mp4` (or `.mp3` with `-a`) file in the output directory, not only the ones just downloaded.",
        "Under `-p` yt-dlp is not run at all.",
    ],
    see_also = ["download_audio_files"],
    section = "Audio & Video")
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
args, unknown = parser.parse_known_args()

# Main
def main():

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

# Start
if __name__ == "__main__":
    system.run_main(main)
