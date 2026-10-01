# Imports
import json
import shutil

# Local imports
import joybox.config as config
import joybox.logger as logger
import joybox.command as command
import joybox.programs as programs
import joybox.strings as strings
import joybox.network as network
import joybox.rumble as rumble
import joybox.paths as paths
import joybox.containers as containers
import joybox.datautils as datautils
import joybox.fileops as fileops
import joybox.settings as settings

# Hard safety cap on concurrent fragment downloads. yt-dlp's -N runs multiple
# fragment downloads per video in parallel; too many parallel connections gets
# the client rate-limited or IP-banned by YouTube, so requested values are
# clamped to this ceiling regardless of config.
MAX_CONCURRENT_FRAGMENTS = 8

# Locate a JavaScript runtime for yt-dlp's YouTube nsig "n challenge" solver.
# Recent yt-dlp needs an external JS runtime (Deno preferred) to compute the nsig
# value; without one YouTube returns only storyboard images and downloads fail with
# "Requested format is not available". Deno is installed by the JoyBox Bootstrap
# layer at ~/.deno/bin, which is NOT on the download subprocess PATH, so we locate
# it explicitly and hand yt-dlp "--js-runtimes deno:<path>".
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

# Get yt-dlp program
def get_youtube_tool():
    if programs.is_tool_installed("YtDlp"):
        return programs.get_tool_program("YtDlp")
    return None

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

# Parse image search item
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

# Find images
def find_images(
    search_name,
    image_type = None,
    image_size = None,
    image_dimensions = None,
    num_results = 20,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get authorization info
    google_search_engine_id = settings.get_value("UserData.Scraping", "google_search_engine_id")
    google_search_engine_api_key = settings.get_value("UserData.Scraping", "google_search_engine_api_key")
    if not google_search_engine_id or not google_search_engine_api_key:
        logger.log_error("Google search engine id and api key must be set in UserData.Scraping")
        return []

    # Get search url
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
    search_url += "&cx=%s" % strings.encode_url_string(google_search_engine_id)
    search_url += "&key=%s" % strings.encode_url_string(google_search_engine_api_key)

    # Get search results
    image_json = network.get_remote_json(
        url = search_url,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not isinstance(image_json, dict):
        logger.log_error("Unable to find images for '%s'" % search_name)
        return []

    # Build search results
    requested_dimensions = parse_image_dimensions(image_dimensions)
    image_json_items = image_json.get("items")
    if not isinstance(image_json_items, list):
        return []
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

    # Return search results
    return sorted(search_results, key=lambda x: x.get_relevance(), reverse = True)

# Parse video search line
def parse_video_search_line(line):
    try:
        line_json = json.loads(line)
    except ValueError:
        return None
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

# Find videos
def find_videos(
    search_name,
    num_results = 20,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    youtube_tool = get_youtube_tool()
    if not youtube_tool:
        logger.log_error("YtDlp was not found")
        return []

    # Get search command
    try:
        num_results = max(1, int(num_results))
    except (TypeError, ValueError):
        num_results = 20
    search_cmd = [
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

    # Run search command
    search_output = command.run_output_command(
        cmd = search_cmd,
        options = command.create_command_options(
            blocking_processes = [youtube_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Build search results
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

    # Return search results
    return sorted(search_results, key=lambda d: d.get_duration())

# Get playlist video ids
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
    youtube_tool = get_youtube_tool()
    if not youtube_tool:
        logger.log_error("YtDlp was not found")
        return []

    # Enumerate id + canonical url without downloading (site-agnostic: the url is
    # used verbatim so non-YouTube sites work; the id is used for archive matching)
    list_cmd = [
        youtube_tool,
        "--flat-playlist",
        "--print", "%(id)s\t%(url)s"
    ]
    list_cmd += get_cookie_args(cookie_source)
    list_cmd += [video_url]

    # Run and parse unique ids (preserving order)
    output = command.run_output_command(
        cmd = list_cmd,
        options = command.create_command_options(blocking_processes = [youtube_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
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

# Download video
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
    youtube_tool = get_youtube_tool()
    if not youtube_tool:
        logger.log_error("YtDlp was not found")
        return False

    # Get targets
    video_urls = list(video_url) if isinstance(video_url, (list, tuple)) else [video_url]
    video_urls = [url for url in video_urls if isinstance(url, str) and url]
    if not video_urls:
        logger.log_error("No video url given to download")
        return False

    # Clamp concurrency to a safe range (>= 1, <= MAX_CONCURRENT_FRAGMENTS)
    try:
        concurrent_fragments = int(concurrent_fragments)
    except (TypeError, ValueError):
        concurrent_fragments = 1
    if concurrent_fragments < 1:
        concurrent_fragments = 1
    if concurrent_fragments > MAX_CONCURRENT_FRAGMENTS:
        logger.log_warning(f"Requested {concurrent_fragments} concurrent fragments; clamping to safe maximum of {MAX_CONCURRENT_FRAGMENTS}")
        concurrent_fragments = MAX_CONCURRENT_FRAGMENTS

    # Get download command
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
    if audio_only:
        download_cmd += [
            "--extract-audio",
            "--audio-format", "mp3",
            "--embed-thumbnail",
            "--embed-metadata",
            "--format", "bestaudio/best"
        ]
    else:
        download_cmd += [
            "--recode-video", "mp4"
        ]
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

    # Run download command
    media_files_before = get_media_files(output_dir)
    logger.log_info(f"Executing download command: {' '.join(download_cmd[:5])}...")
    code = command.run_returncode_command(
        cmd = download_cmd,
        options = command.create_command_options(
            blocking_processes = [youtube_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    logger.log_info(f"Download command completed with return code: {code}")

    # Check what was downloaded
    new_files_count = 0
    if paths.is_path_directory(output_dir):
        new_files_count = len(get_media_files(output_dir) - media_files_before)
        logger.log_info(f"Found {new_files_count} new media files after download")
    elif paths.is_path_valid(output_dir):
        logger.log_warning(f"Output directory doesn't exist after download: {output_dir}")

    # yt-dlp exits 1 for partial failures (including videos already archived);
    # anything above that is a serious error
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

    # Sanitize filenames
    if sanitize_filenames:
        logger.log_info("Starting filename sanitization...")

        # Get sanitize dir
        sanitize_dir = None
        if paths.is_path_file(output_file):
            sanitize_dir = paths.get_filename_directory(output_file)
        elif paths.is_path_directory(output_dir):
            sanitize_dir = output_dir

        # Sanitize files in dir
        if sanitize_dir:
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
        else:
            logger.log_warning("No sanitization directory found")

    # Return success
    logger.log_info("Video download process completed successfully")
    return True
