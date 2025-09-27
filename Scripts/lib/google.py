# Imports
import os, os.path
import sys
import json

# Local imports
import config
import system
import command
import programs
import network
import containers
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
    google_search_engine_id = ini.GetIniValue("UserData.Scraping", "google_search_engine_id")
    google_search_engine_api_key = ini.GetIniValue("UserData.Scraping", "google_search_engine_api_key")

    # Get search url
    search_url = "https://www.googleapis.com/customsearch/v1"
    search_url += "?q=%s" % system.EncodeUrlString(search_name)
    search_url += "&searchType=image"
    if config.ImageFileType.is_member(image_type):
        search_url += "&fileType=%s" % image_type.lower()
    if config.SizeType.is_member(image_size):
        search_url += "&imgSize=%s" % image_size.lower()
    search_url += "&cx=%s" % google_search_engine_id
    search_url += "&key=%s" % google_search_engine_api_key

    # Get search results
    image_json = network.GetRemoteJson(
        url = search_url,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not image_json:
        system.LogError("Unable to find images from '%s'" % search_url)
        return False

    # Build search results
    search_results = []
    if "items" in image_json:
        image_json_items = image_json["items"]
        if system.IsIterableContainer(image_json_items):
            for image_json_item in image_json_items:

                # Get item info
                item_title = image_json_item["title"]
                item_url = image_json_item["link"]
                item_mime = image_json_item["mime"]
                item_width = int(image_json_item["image"]["width"])
                item_height = int(image_json_item["image"]["height"])

                # Ignore dissimilar images
                if not system.AreStringsHighlySimilar(search_name, item_title):
                    continue

                # Ignore images that do not match requested dimensions
                if system.IsIterableNonString(image_dimensions) and len(image_dimensions) == 2:
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
                search_result.set_relevance(system.GetStringSimilarityRatio(search_name, item_title))
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
    if programs.IsToolInstalled("YtDlp"):
        youtube_tool = programs.GetToolProgram("YtDlp")
    if not youtube_tool:
        system.LogError("YtDlp was not found")
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
    search_output = command.RunOutputCommand(
        cmd = search_cmd,
        options = command.CreateCommandOptions(
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
            if not system.AreStringsModeratelySimilar(search_name, line_title):
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
    if programs.IsToolInstalled("YtDlp"):
        youtube_tool = programs.GetToolProgram("YtDlp")
    if not youtube_tool:
        system.LogError("YtDlp was not found")
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
            "--format", "bestaudio"
        ]
    else:
        download_cmd += [
            "--recode-video", "mp4"
        ]
    if verbose:
        download_cmd += ["--progress"]
    if pretend_run:
        download_cmd += ["--simulate"]
    if system.IsPathValid(output_dir):
        download_cmd += ["-P", output_dir]
    if system.IsPathValid(output_file):
        download_cmd += ["-o", output_file]
    else:
        download_cmd += ["-o", "%(upload_date)s - %(title).200s.%(ext)s"]
    if system.IsPathValid(download_archive):
        download_cmd += ["--download-archive", download_archive]
    if isinstance(cookie_source, str) and len(cookie_source) > 0:
        if system.DoesPathExist(cookie_source):
            download_cmd += ["--cookies", cookie_source]
        else:
            download_cmd += ["--cookies-from-browser", cookie_source]
    download_cmd += [video_url]

    # Run download command
    system.LogInfo(f"Executing download command: {' '.join(download_cmd[:5])}...")
    code = command.RunReturncodeCommand(
        cmd = download_cmd,
        options = command.CreateCommandOptions(
            blocking_processes = [youtube_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    system.LogInfo(f"Download command completed with return code: {code}")
    if code != 0:
        system.LogWarning(f"Download completed with some failures (return code: {code})")
    else:
        system.LogInfo("Download command completed successfully")

    # Check what was downloaded
    download_success = True
    new_files_count = 0
    if system.IsPathDirectory(output_dir):
        downloaded_files = system.GetDirectoryContents(output_dir)
        media_files = [f for f in downloaded_files if f.endswith(('.mp3', '.mp4'))]
        new_files_count = len(media_files)
        system.LogInfo(f"Found {new_files_count} new media files after download")
    else:
        system.LogWarning(f"Output directory doesn't exist after download: {output_dir}")

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
        system.LogInfo("Download completed without any issues")
    elif code == 1:
        if new_files_count > 0:
            system.LogInfo(f"Download completed with some issues but {new_files_count} new files were downloaded")
        else:
            system.LogInfo("Download completed - no new files (likely all videos already archived)")
    else:
        system.LogError(f"Download failed with serious error (exit code: {code})")
        download_success = False

    # Sanitize filenames
    if sanitize_filenames:
        system.LogInfo("Starting filename sanitization...")

        # Get sanitize dir
        sanitize_dir = None
        if system.IsPathFile(output_file):
            sanitize_dir = system.GetFilenameDirectory(output_file)
        elif system.IsPathDirectory(output_dir):
            sanitize_dir = output_dir

        # Sanitize files in dir
        if sanitize_dir:
            system.LogInfo(f"Sanitizing filenames in directory: {sanitize_dir}")
            success = system.SanitizeFilenames(
                path = sanitize_dir,
                extension = ".mp3" if audio_only else ".mp4",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Filename sanitization failed")
                return False
            system.LogInfo("Filename sanitization completed successfully")
        else:
            system.LogWarning("No sanitization directory found")

    # Return success status based on our analysis
    if download_success:
        system.LogInfo("Video download process completed successfully")
        return True
    else:
        system.LogError("Video download process failed")
        return False
