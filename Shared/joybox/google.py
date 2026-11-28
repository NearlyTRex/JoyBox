# Imports
import shutil

# Local imports
from joybox import config
from joybox import logger
from joybox import serialization
from joybox import command
from joybox import commandbase
from joybox import programs
from joybox import strings
from joybox import network
from joybox import rumble
from joybox import paths
from joybox import containers
from joybox import datautils
from joybox import fileops
from joybox import settings

# Hard safety cap on concurrent fragment downloads. yt-dlp's -N runs multiple
# fragment downloads per video in parallel; too many parallel connections gets
# the client rate-limited or IP-banned by YouTube, so requested values are
# clamped to this ceiling regardless of config.
MAX_CONCURRENT_FRAGMENTS = 8

# yt-dlp's "--js-runtimes deno:<path>", without which YouTube's nsig challenge fails
# with "Requested format is not available"; Bootstrap installs Deno in ~/.deno/bin,
# which is not on the download's PATH
def get_javascript_runtime_args():
    candidates = [paths.expand_path("~/.deno/bin/deno"), shutil.which("deno")]
    for deno_path in candidates:
        if deno_path and paths.is_path_file(deno_path):
            return ["--js-runtimes", f"deno:{deno_path}"]
    logger.log_warning("No Deno JavaScript runtime found; YouTube downloads may fail the nsig 'n challenge' (see yt-dlp EJS wiki).")
    return []

# Google custom search returns at most this many results per request
MAX_IMAGE_SEARCH_RESULTS = 10

# yt-dlp prints this for a field the extractor did not provide
YTDLP_MISSING_FIELD = "NA"

# Get yt-dlp cookie args
def get_cookie_args(cookie_source):
    if not isinstance(cookie_source, str) or len(cookie_source) == 0:
        return []
    if paths.does_path_exist(cookie_source):
        return ["--cookies", cookie_source]
    return ["--cookies-from-browser", cookie_source]

# Parse requested image dimensions
def parse_image_dimensions(image_dimensions):
    if not datautils.is_iterable_non_string(image_dimensions):
        return None
    image_dimensions = list(image_dimensions)
    if len(image_dimensions) != 2:
        return None
    try:
        return tuple(int(value) for value in image_dimensions)
    except (TypeError, ValueError):
        return None

# Title, url, mime, width and height of one custom search image result; None when a field is missing or malformed
def parse_image_search_item(image_json_item):
    if not isinstance(image_json_item, dict):
        return None
    item_title = image_json_item.get("title")
    item_url = image_json_item.get("link")
    item_image = image_json_item.get("image")
    if not isinstance(item_title, str) or not isinstance(item_url, str) or not item_url:
        return None
    if not isinstance(item_image, dict):
        return None
    try:
        item_width = int(item_image.get("width"))
        item_height = int(item_image.get("height"))
    except (TypeError, ValueError):
        return None
    return (item_title, item_url, image_json_item.get("mime"), item_width, item_height)

# The custom search image query url for at most MAX_IMAGE_SEARCH_RESULTS results, with the
# file type and size filters when given
def _build_image_search_url(search_name, image_type, image_size, num_results):
    try:
        num_results = int(num_results)
    except (TypeError, ValueError):
        num_results = MAX_IMAGE_SEARCH_RESULTS
    num_results = max(1, min(num_results, MAX_IMAGE_SEARCH_RESULTS))
    search_url = "https://www.googleapis.com/customsearch/v1"
    search_url += "?q=%s" % strings.encode_url_string(search_name)
    search_url += "&searchType=image"
    search_url += "&num=%d" % num_results
    image_type = config.ImageFileType.from_enum(image_type)
    if image_type:
        search_url += "&fileType=%s" % image_type.cvalue.lstrip(".").lower()
    image_size = config.SizeType.from_enum(image_size)
    if image_size:
        search_url += "&imgSize=%s" % image_size.val().lower()
    return search_url

# AssetSearchResults for the well-formed image items whose titles closely match the name
# and, when requested, whose dimensions match exactly
def _build_image_search_results(search_name, image_json_items, requested_dimensions):
    search_results = []
    for image_json_item in image_json_items:

        # Get item info
        item_info = parse_image_search_item(image_json_item)
        if not item_info:
            continue
        item_title, item_url, item_mime, item_width, item_height = item_info

        # Ignore dissimilar images
        if not strings.are_strings_highly_similar(search_name, item_title):
            continue

        # Ignore images that do not match requested dimensions
        if requested_dimensions and (item_width, item_height) != requested_dimensions:
            continue

        # Add search result
        search_result = containers.AssetSearchResult()
        search_result.set_title(item_title)
        search_result.set_url(item_url)
        search_result.set_mime(item_mime)
        search_result.set_width(item_width)
        search_result.set_height(item_height)
        search_result.set_relevance(strings.get_string_similarity_ratio(search_name, item_title))
        search_results.append(search_result)
    return search_results

# Google custom search images similar to the name, filtered by type, size and exact dimensions, best match first; empty without the API settings
def find_images(
    search_name,
    image_type = None,
    image_size = None,
    image_dimensions = None,
    num_results = 20,
    verbose = False,
    exit_on_failure = False):

    # Get authorization info
    google_search_engine_id = settings.get_value("UserData.Scraping", "google_search_engine_id")
    google_search_engine_api_key = settings.get_value("UserData.Scraping", "google_search_engine_api_key")
    if not google_search_engine_id or not google_search_engine_api_key:
        logger.log_error("Google search engine id and api key must be set in UserData.Scraping")
        return []

    # Get search url
    search_url = _build_image_search_url(search_name, image_type, image_size, num_results)

    # Get search results
    image_json = network.get_remote_json(
        url = search_url,
        params = {"cx": google_search_engine_id, "key": google_search_engine_api_key},
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if not isinstance(image_json, dict):
        logger.log_error("Unable to find images for '%s'" % search_name)
        return []

    # Build search results
    requested_dimensions = parse_image_dimensions(image_dimensions)
    image_json_items = image_json.get("items")
    if not isinstance(image_json_items, list):
        return []
    search_results = _build_image_search_results(search_name, image_json_items, requested_dimensions)

    # Return search results
    return sorted(search_results, key=lambda x: x.get_relevance(), reverse = True)

# Title, channel, duration, duration string and url from one yt-dlp JSON line; None when the line is not a usable result
def parse_video_search_line(line):
    line_json = serialization.parse_json_or_none(line)
    if not isinstance(line_json, dict):
        return None
    line_title = line_json.get("title")
    line_url = line_json.get("url")
    if not isinstance(line_title, str) or not isinstance(line_url, str) or not line_url:
        return None
    line_channel = line_json.get("channel") or "Unknown"
    line_duration = line_json.get("duration")
    if isinstance(line_duration, bool) or not isinstance(line_duration, (int, float)):
        line_duration = 0
    line_duration_str = line_json.get("duration_string") or "Unknown"
    return (line_title, line_channel, line_duration, line_duration_str, line_url)

# The yt-dlp flat search command dumping JSON for num_results results (20 when unparseable)
def _build_video_search_command(youtube_tool, search_name, num_results):
    try:
        num_results = max(1, int(num_results))
    except (TypeError, ValueError):
        num_results = 20
    return [
        youtube_tool,
        "ytsearch%d:%s" % (num_results, search_name),
        "--dump-json",
        "--default-search", "ytsearch",
        "--no-playlist",
        "--no-check-certificate",
        "--geo-bypass",
        "--flat-playlist",
        "--skip-download",
        "--quiet",
        "--ignore-errors"
    ]

# AssetSearchResults for the usable yt-dlp output lines whose titles resemble the name
def _build_video_search_results(search_name, search_output):
    search_results = []
    for line in (search_output or "").splitlines():

        # Get line info
        line_info = parse_video_search_line(line)
        if not line_info:
            continue
        line_title, line_channel, line_duration, line_duration_str, line_url = line_info

        # Ignore dissimilar videos
        if not strings.are_strings_moderately_similar(search_name, line_title):
            continue

        # Add search result
        search_result = containers.AssetSearchResult()
        search_result.set_title(line_title)
        search_result.set_description(f"{line_title} ({line_channel}) [{line_duration_str}]")
        search_result.set_duration(line_duration)
        search_result.set_url(line_url)
        search_results.append(search_result)
    return search_results

# YouTube search results via yt-dlp whose titles resemble the name, shortest first; empty when yt-dlp is missing
def find_videos(
    search_name,
    num_results = 20,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    youtube_tool = programs.find_tool_program("YtDlp")
    if not youtube_tool:
        return []

    # Get search command
    search_cmd = _build_video_search_command(youtube_tool, search_name, num_results)

    # Run search command
    search_output = command.run_output_command(
        cmd = search_cmd,
        options = commandbase.create_command_options(
            blocking_processes = [youtube_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Build search results
    search_results = _build_video_search_results(search_name, search_output)

    # Return search results
    return sorted(search_results, key=lambda d: d.get_duration())

# The yt-dlp flat-playlist command printing "id<TAB>url" for each entry of the url
def _build_playlist_list_command(youtube_tool, video_url, cookie_source):
    list_cmd = [
        youtube_tool,
        "--flat-playlist",
        "--print", "%(id)s\t%(url)s"
    ]
    list_cmd += get_cookie_args(cookie_source)
    list_cmd += [video_url]
    return list_cmd

# Ordered unique (id, url) pairs of a playlist or channel, listed by yt-dlp without downloading; Rumble channels use the scraper
def get_playlist_video_ids(
    video_url,
    cookie_source = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Rumble channel pages need bespoke enumeration: yt-dlp's RumbleChannel
    # extractor no longer parses the current markup (it returns 0 items), so
    # scrape the video urls from the channel page and let yt-dlp download each.
    if rumble.is_rumble_channel_url(video_url):
        return rumble.get_channel_video_urls(
            video_url,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Get tool
    youtube_tool = programs.find_tool_program("YtDlp")
    if not youtube_tool:
        return []

    # Enumerate id + canonical url without downloading (site-agnostic: the url is
    # used verbatim so non-YouTube sites work; the id is used for archive matching)
    list_cmd = _build_playlist_list_command(youtube_tool, video_url, cookie_source)

    # Run and parse unique ids (preserving order)
    output = command.run_output_command(
        cmd = list_cmd,
        options = commandbase.create_command_options(blocking_processes = [youtube_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return parse_playlist_video_ids(output)

# Ordered unique (id, url) pairs from yt-dlp's "id<TAB>url" lines; a missing url becomes empty
# and lines without an id are dropped
def parse_playlist_video_ids(output):
    videos = []
    seen = set()
    for line in (output or "").splitlines():
        parts = line.split("\t")
        vid = parts[0].strip()
        url = parts[1].strip() if len(parts) > 1 else ""
        if url == YTDLP_MISSING_FIELD:
            url = ""
        if vid and vid != YTDLP_MISSING_FIELD and vid not in seen:
            seen.add(vid)
            videos.append((vid, url))
    return videos

# Get downloaded media files
def get_media_files(output_dir):
    if not paths.is_path_directory(output_dir):
        return set()
    return {f for f in paths.get_directory_contents(output_dir) if f.endswith((".mp3", ".mp4"))}

# The requested fragment concurrency as an int of at least 1, clamped with a warning to
# MAX_CONCURRENT_FRAGMENTS; 1 when unparseable
def _clamp_concurrent_fragments(concurrent_fragments):
    try:
        concurrent_fragments = int(concurrent_fragments)
    except (TypeError, ValueError):
        concurrent_fragments = 1
    concurrent_fragments = max(concurrent_fragments, 1)
    if concurrent_fragments > MAX_CONCURRENT_FRAGMENTS:
        logger.log_warning(f"Requested {concurrent_fragments} concurrent fragments; clamping to safe maximum of {MAX_CONCURRENT_FRAGMENTS}")
        concurrent_fragments = MAX_CONCURRENT_FRAGMENTS
    return concurrent_fragments

# The yt-dlp format arguments: mp3 extraction with thumbnail and metadata, or an mp4 recode
def _get_download_format_args(audio_only):
    if audio_only:
        return [
            "--extract-audio",
            "--audio-format", "mp3",
            "--embed-thumbnail",
            "--embed-metadata",
            "--format", "bestaudio/best"
        ]
    return [
        "--recode-video", "mp4"
    ]

# The yt-dlp download command for the urls, with concurrency, format, output, archive and
# cookie arguments; pretend runs only simulate
def _build_download_command(
    youtube_tool,
    video_urls,
    audio_only,
    output_file,
    output_dir,
    download_archive,
    cookie_source,
    concurrent_fragments,
    verbose,
    pretend_run):
    download_cmd = [
        youtube_tool,
        "--windows-filenames",
        "--continue",
        "--format-sort", "res,ext:mp4:m4a",
        "--sleep-interval", "3",
        "--max-sleep-interval", "5"
    ]
    if concurrent_fragments > 1:
        download_cmd += ["--concurrent-fragments", str(concurrent_fragments)]
    download_cmd += get_javascript_runtime_args()
    download_cmd += _get_download_format_args(audio_only)
    if verbose:
        download_cmd += ["--progress"]
    if pretend_run:
        download_cmd += ["--simulate"]
    if paths.is_path_valid(output_dir):
        download_cmd += ["-P", output_dir]
    if paths.is_path_valid(output_file):
        download_cmd += ["-o", output_file]
    else:
        download_cmd += ["-o", "%(upload_date)s - %(title).200s.%(ext)s"]
    if paths.is_path_valid(download_archive):
        download_cmd += ["--download-archive", download_archive]
    download_cmd += get_cookie_args(cookie_source)
    download_cmd += video_urls
    return download_cmd

# How many media files the output directory gained since media_files_before; 0, with a
# warning when a named directory vanished, when there is no directory
def _count_new_media_files(output_dir, media_files_before):
    new_files_count = 0
    if paths.is_path_directory(output_dir):
        new_files_count = len(get_media_files(output_dir) - media_files_before)
        logger.log_info(f"Found {new_files_count} new media files after download")
    elif paths.is_path_valid(output_dir):
        logger.log_warning(f"Output directory doesn't exist after download: {output_dir}")
    return new_files_count

# Log how the download went; False on a serious error. yt-dlp exits 1 for partial failures
# (including videos already archived); anything above that is a serious error
def _report_download_result(code, new_files_count):
    if code == 0:
        logger.log_info("Download completed without any issues")
    elif code == 1:
        if new_files_count > 0:
            logger.log_info(f"Download completed with some issues but {new_files_count} new files were downloaded")
        else:
            logger.log_info("Download completed - no new files (likely all videos already archived)")
    else:
        logger.log_error(f"Download failed with serious error (exit code: {code})")
        logger.log_error("Video download process failed")
        return False
    return True

# Run the download, then count the new media files in output_dir and report the result;
# False on a serious yt-dlp error
def _run_and_check_download(youtube_tool, download_cmd, output_dir, verbose, pretend_run, exit_on_failure):
    media_files_before = get_media_files(output_dir)
    code = _run_download_command(youtube_tool, download_cmd, verbose, pretend_run, exit_on_failure)
    new_files_count = _count_new_media_files(output_dir, media_files_before)
    return _report_download_result(code, new_files_count)

# Sanitize the downloaded mp3 or mp4 filenames in the output file's folder or the output
# directory; False when sanitizing fails, True (with a warning) when there is no folder
def _sanitize_downloaded_filenames(
    audio_only,
    output_file,
    output_dir,
    verbose,
    pretend_run,
    exit_on_failure):
    logger.log_info("Starting filename sanitization...")

    # Get sanitize dir
    sanitize_dir = None
    if paths.is_path_file(output_file):
        sanitize_dir = paths.get_filename_directory(output_file)
    elif paths.is_path_directory(output_dir):
        sanitize_dir = output_dir
    if not sanitize_dir:
        logger.log_warning("No sanitization directory found")
        return True

    # Sanitize files in dir
    logger.log_info(f"Sanitizing filenames in directory: {sanitize_dir}")
    success = fileops.sanitize_filenames(
        path = sanitize_dir,
        extension = ".mp3" if audio_only else ".mp4",
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Filename sanitization failed")
        return False
    logger.log_info("Filename sanitization completed successfully")
    return True

# The non-empty string urls of one url or a list or tuple of them; logs when there are none
def _get_download_urls(video_url):
    video_urls = list(video_url) if isinstance(video_url, (list, tuple)) else [video_url]
    video_urls = [url for url in video_urls if isinstance(url, str) and url]
    if not video_urls:
        logger.log_error("No video url given to download")
    return video_urls

# Run the download command, blocking on yt-dlp and logging its start and return code
def _run_download_command(youtube_tool, download_cmd, verbose, pretend_run, exit_on_failure):
    logger.log_info(f"Executing download command: {' '.join(download_cmd[:5])}...")
    code = command.run_returncode_command(
        cmd = download_cmd,
        options = commandbase.create_command_options(
            blocking_processes = [youtube_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    logger.log_info(f"Download command completed with return code: {code}")
    return code

# Download videos (or mp3 audio) with yt-dlp, optionally sanitizing filenames after; False on a serious yt-dlp error or failed sanitize
def download_video(
    video_url,
    audio_only = False,
    output_file = None,
    output_dir = None,
    download_archive = None,
    cookie_source = None,
    concurrent_fragments = 1,
    sanitize_filenames = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    youtube_tool = programs.find_tool_program("YtDlp")
    if not youtube_tool:
        return False

    # Get targets
    video_urls = _get_download_urls(video_url)
    if not video_urls:
        return False

    # Get download command, with concurrency clamped to a safe range
    download_cmd = _build_download_command(
        youtube_tool, video_urls, audio_only, output_file, output_dir, download_archive,
        cookie_source, _clamp_concurrent_fragments(concurrent_fragments), verbose, pretend_run)

    # Run download command and check what was downloaded
    if not _run_and_check_download(youtube_tool, download_cmd, output_dir, verbose, pretend_run, exit_on_failure):
        return False

    # Sanitize filenames
    if sanitize_filenames and not _sanitize_downloaded_filenames(
        audio_only, output_file, output_dir, verbose, pretend_run, exit_on_failure):
        return False

    # Return success
    logger.log_info("Video download process completed successfully")
    return True
