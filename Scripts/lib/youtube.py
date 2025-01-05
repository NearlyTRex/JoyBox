# Imports
import os, os.path
import sys
import json

# Local imports
import config
import system
import environment
import command
import programs

# Get search results
def GetSearchResults(
    search_terms,
    num_results = 10,
    sort_by_duration = False,
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
        "ytsearch%d:\"%s\"" % (num_results, search_terms),
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
        options = command.CommandOptions(
            shell = True,
            blocking_processes = [youtube_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Parse search results
    search_results = []
    for line in search_output.split("\n"):
        try:
            search_result = json.loads(line)
            if "duration" not in search_result:
                continue
            if search_result["duration"] == None:
                continue
            search_results.append(search_result)
        except Exception as e:
            pass

    # Sort search results by duration
    if sort_by_duration:
        search_results = sorted(search_results, key=lambda d: d["duration"])

    # Return search results
    return search_results

# Download video
def DownloadVideo(
    video_url,
    output_file = None,
    output_dir = None,
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
        "--recode-video", "mp4"
    ]
    if isinstance(cookie_source, str) and len(cookie_source) > 0:
        if system.DoesPathExist(cookie_source):
            download_cmd += ["--cookies", cookie_source]
        else:
            download_cmd += ["--cookies-from-browser", cookie_source]
    if verbose:
        download_cmd += ["--progress"]
    if pretend_run:
        download_cmd += ["--simulate"]
    if system.IsPathValid(output_dir):
        download_cmd += [
            "-P", output_dir
        ]
    if system.IsPathValid(output_file):
        download_cmd += [
            "-o", output_file
        ]
    else:
        download_cmd += [
            "-o", "%(title)s.%(ext)s"
        ]
    download_cmd += [video_url]

    # Run download command
    code = command.RunBlockingCommand(
        cmd = download_cmd,
        options = command.CommandOptions(
            blocking_processes = [youtube_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Sanitize filenames
    if sanitize_filenames:

        # Get sanitize dir
        sanitize_dir = None
        if system.IsPathFile(output_file):
            sanitize_dir = system.GetFilenameDirectory(output_file)
        elif system.IsPathDirectory(output_dir):
            sanitize_dir = output_dir

        # Replace invalid path characters
        for obj in system.GetDirectoryContents(sanitize_dir):
            obj_path = system.JoinPaths(sanitize_dir, obj)
            if system.IsPathFile(obj_path) and obj.endswith(".mp4"):
                system.MoveFileOrDirectory(
                    src = obj_path,
                    dest = system.JoinPaths(sanitize_dir, system.ReplaceInvalidPathCharacters(obj)),
                    skip_existing = True,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)

    # Should be successful
    return True
