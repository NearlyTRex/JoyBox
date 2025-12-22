# Imports
import os, os.path
import sys
import json

# Local imports
import config
import system
import logger
import command
import programs
import strings
import network
import paths
import containers
import datautils
import fileops
import ini

# Find images
def FindImages(
    search_name,
    image_type = None,
    image_size = None,
    image_dimensions = None,
    num_results = 20,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get authorization info
    google_search_engine_id = ini.get_ini_value("UserData.Scraping", "google_search_engine_id")
    google_search_engine_api_key = ini.get_ini_value("UserData.Scraping", "google_search_engine_api_key")

    # Get search url
    search_url = "https://www.googleapis.com/customsearch/v1"
    search_url += "?q=%s" % strings.encode_url_string(search_name)
    search_url += "&searchType=image"
    if config.ImageFileType.is_member(image_type):
        search_url += "&fileType=%s" % image_type.lower()
    if config.SizeType.is_member(image_size):
        search_url += "&imgSize=%s" % image_size.lower()
    search_url += "&cx=%s" % google_search_engine_id
    search_url += "&key=%s" % google_search_engine_api_key

    # Get search results
    image_json = network.get_remote_json(
        url = search_url,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not image_json:
        logger.log_error("Unable to find images from '%s'" % search_url)
        return False

    # Build search results
    search_results = []
    if "items" in image_json:
        image_json_items = image_json["items"]
        if datautils.is_iterable_container(image_json_items):
            for image_json_item in image_json_items:

                # Get item info
                item_title = image_json_item["title"]
                item_url = image_json_item["link"]
                item_mime = image_json_item["mime"]
                item_width = int(image_json_item["image"]["width"])
                item_height = int(image_json_item["image"]["height"])

                # Ignore dissimilar images
                if not strings.are_strings_highly_similar(search_name, item_title):
                    continue

                # Ignore images that do not match requested dimensions
                if datautils.is_iterable_non_string(image_dimensions) and len(image_dimensions) == 2:
                    requested_width, requested_height = map(int, image_dimensions)
                    if item_width != requested_width or item_height != requested_height:
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

# Find videos
def FindVideos(
    search_name,
    num_results = 20,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    youtube_tool = None
    if programs.is_tool_installed("YtDlp"):
        youtube_tool = programs.get_tool_program("YtDlp")
    if not youtube_tool:
        logger.log_error("YtDlp was not found")
        return False

    # Get search command
    search_cmd = [
        youtube_tool,
        "ytsearch%d:\"%s\"" % (num_results, search_name),
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
            shell = True,
            blocking_processes = [youtube_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Build search results
    search_results = []
    for line in search_output.split("\n"):
        try:

            # Get line info
            line_json = json.loads(line)
            line_id = line_json["id"] if "id" in line_json else ""
            line_title = line_json["title"] if "title" in line_json else ""
            line_channel = line_json["channel"] if "channel" in line_json else "Unknown"
            line_duration = line_json["duration"] if "duration" in line_json and line_json["duration"] else 0
            line_duration_str = line_json["duration_string"] if "duration_string" in line_json and line_json["duration_string"] else "Unknown"
            line_url = line_json["url"] if "url" in line_json else ""

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
        except Exception as e:
            pass

    # Return search results
    return sorted(search_results, key=lambda d: d.get_duration())

# Download video
def DownloadVideo(
    video_url,
    audio_only = False,
    output_file = None,
    output_dir = None,
    download_archive = None,
    cookie_source = None,
    sanitize_filenames = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    youtube_tool = None
    if programs.is_tool_installed("YtDlp"):
        youtube_tool = programs.get_tool_program("YtDlp")
    if not youtube_tool:
        logger.log_error("YtDlp was not found")
        return False

    # Get download command
    download_cmd = [
        youtube_tool,
        "--windows-filenames",
        "--format-sort", "res,ext:mp4:m4a",
        "--sleep-interval", "3",
        "--max-sleep-interval", "5"
    ]
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
    if isinstance(cookie_source, str) and len(cookie_source) > 0:
        if paths.does_path_exist(cookie_source):
            download_cmd += ["--cookies", cookie_source]
        else:
            download_cmd += ["--cookies-from-browser", cookie_source]
    download_cmd += [video_url]

    # Run download command
    logger.log_info(f"Executing download command: {' '.join(download_cmd[:5])}...")
    code = command.run_returncode_command(
        cmd = download_cmd,
        options = command.create_command_options(
            blocking_processes = [youtube_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    logger.log_info(f"Download command completed with return code: {code}")
    if code != 0:
        logger.log_warning(f"Download completed with some failures (return code: {code})")
    else:
        logger.log_info("Download command completed successfully")

    # Check what was downloaded
    download_success = True
    new_files_count = 0
    if paths.is_path_directory(output_dir):
        downloaded_files = paths.get_directory_contents(output_dir)
        media_files = [f for f in downloaded_files if f.endswith(('.mp3', '.mp4'))]
        new_files_count = len(media_files)
        logger.log_info(f"Found {new_files_count} new media files after download")
    else:
        logger.log_warning(f"Output directory doesn't exist after download: {output_dir}")

    # Determine if the operation was successful
    # yt-dlp returns exit code 1 for partial failures, but this doesn't mean total failure
    # Success cases:
    # - Exit code 0 (complete success)
    # - Exit code 1 but with new files downloaded (partial success)
    # - Exit code 1 but all videos were already archived (nothing new to download)
    # Failure case:
    # - Exit code > 1 (serious error)
    # - Exit code 1 with no progress and genuine failures (not just archives)
    if code == 0:
        logger.log_info("Download completed without any issues")
    elif code == 1:
        if new_files_count > 0:
            logger.log_info(f"Download completed with some issues but {new_files_count} new files were downloaded")
        else:
            logger.log_info("Download completed - no new files (likely all videos already archived)")
    else:
        logger.log_error(f"Download failed with serious error (exit code: {code})")
        download_success = False

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

    # Return success status based on our analysis
    if download_success:
        logger.log_info("Video download process completed successfully")
        return True
    else:
        logger.log_error("Video download process failed")
        return False
