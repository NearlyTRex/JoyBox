#!/usr/bin/env python3

# Imports
import os, os.path
import sys

# Custom imports
shared_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "Shared"))
sys.path.append(shared_folder)
import joybox.config as config
import joybox.system as system
import joybox.audio as audio
import joybox.arguments as arguments
import joybox.setup as setup
import joybox.logger as logger

# Parse arguments
parser = arguments.ArgumentParser(
    description = "Download new videos from a genre's configured channels as MP3 and back them up to a locker.",
    details = (
        "Takes no URL. The channels come from `story_channels` and `asmr_channels` in\n"
        "`Shared/joybox/config/audio.py`, and only the `Story` and `ASMR` genres download\n"
        "anything; the other genres are accepted but do nothing. For each channel:\n"
        "\n"
        "1. Lists the channel's videos with `yt-dlp --flat-playlist` (Rumble channels are\n"
        "   scraped directly) and drops those already in the channel's download archive,\n"
        "   `Audio/Archive/<genre>/<channel>.txt` under the file metadata directory.\n"
        "2. Downloads the rest in batches of `audio_download_batch_size` (25) with yt-dlp,\n"
        "   extracting MP3 with the thumbnail and metadata embedded, named\n"
        "   `<upload date> - <title>.mp3` and then sanitized.\n"
        "3. After each batch, copies the audio to `Music/<genre>/<channel>` in each locker\n"
        "   selected by `-l`, skipping files already there, and removes the working copies.\n"
        "\n"
        "Each batch works in a temporary directory unless `-o` is given. With `-o` each channel\n"
        "works in `<output_path>/<channel>`, which is kept, and the next run first uploads any\n"
        "audio an interrupted run left there. yt-dlp also resumes partly downloaded videos.\n"
        "\n"
        "Download order follows `audio_download_oldest_first` in the same config file (newest\n"
        "first by default); `--oldest_first` and `--newest_first` override it for one run.\n"
        "Each video is fetched with `audio_download_concurrent_fragments` (4) parallel\n"
        "fragments, capped at 8, with a 3-5 second pause between videos."),
    examples = [
        ("Download new videos from every Story channel", "download_audio_files -g Story"),
        ("Download one channel (case-insensitive, substrings allowed)", "download_audio_files -g Story -n \"Mr Nightmare\""),
        ("Fill in a channel's back catalogue oldest first", "download_audio_files -g Story -n \"Mr Nightmare\" --oldest_first"),
        ("Download ASMR and back it up to the local locker only", "download_audio_files -g ASMR -l Local"),
        ("Use Chrome's cookies", "download_audio_files -g Story -c chrome"),
        ("Use a cookies file", "download_audio_files -g Story -c /path/to/cookies.txt"),
        ("Keep downloads in a folder so an interrupted run can resume", "download_audio_files -g Story -o ~/audio_resume"),
        ("Stage a large backlog in the local locker only, to push later with master_backup", "download_audio_files -g Story -o ~/audio_resume -l Local"),
        ("Show each channel's archive file and target folder without downloading", "download_audio_files -g Story -p -v"),
    ],
    notes = [
        "Re-runs only fetch videos not in the download archive, so the tool is safe to run repeatedly.",
        "YouTube needs the Deno JavaScript runtime to solve its download challenge; without it downloads fail with `Requested format is not available`. Deno is looked for at `~/.deno/bin/deno` and on `PATH`.",
        "If a channel's videos cannot be listed, the whole channel URL is handed to yt-dlp in one pass.",
        "A yt-dlp exit code of 1 counts as success, since it is also what yt-dlp returns when some videos fail or everything was already archived; members-only videos fail this way unless the cookies belong to a member. Higher exit codes stop the run.",
        "Copies to remote lockers happen file by file and print nothing without `-v`. For a large backlog, use `-l Local` and then `master_backup`, which uploads in batches.",
        "Under `-p` no yt-dlp command is run: channels are not listed and nothing is downloaded, but the log still shows each channel's archive file and target folder.",
    ],
    see_also = ["tag_audio_files", "audio_metadata_tool", "generate_playlist", "master_backup", "download_youtube_videos"],
    section = "Audio & Video")
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
args, unknown = parser.parse_known_args()

# Main
def main():

    # Check requirements
    setup.check_requirements()

    # Setup logging
    logger.setup_logging()

    # Resolve download order: explicit flags override the config default (newest
    # wins if both are given); None means "use the config default".
    order_oldest_first = None
    if args.newest_first:
        order_oldest_first = False
    elif args.oldest_first:
        order_oldest_first = True

    # Story
    if args.genre_type == config.AudioGenreType.STORY:
        success = audio.download_story_audio_files(
            channel_name = args.channel_name,
            oldest_first = order_oldest_first,
            cookie_source = args.cookie_source,
            locker_type = args.locker_type,
            output_path = args.output_path,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if not success:
            logger.log_error("Story audio download failed")
            sys.exit(1)

    # ASMR
    elif args.genre_type == config.AudioGenreType.ASMR:
        success = audio.download_asmr_audio_files(
            channel_name = args.channel_name,
            oldest_first = order_oldest_first,
            cookie_source = args.cookie_source,
            locker_type = args.locker_type,
            output_path = args.output_path,
            verbose = args.verbose,
            pretend_run = args.pretend_run,
            exit_on_failure = args.exit_on_failure)
        if not success:
            logger.log_error("ASMR audio download failed")
            sys.exit(1)

# Start
if __name__ == "__main__":
    system.run_main(main)
