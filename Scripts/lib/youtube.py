# Imports
import os, os.path
import sys
import json

# Local imports
import config
import command
import programs
import system
import environment

# Get search results
def GetSearchResults(search_terms, num_results = 10, verbose = False, exit_on_failure = False):

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
            blocking_processes = [youtube_tool]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Parse search results
    search_results = []
    for line in search_output.split("\n"):
        try:
            search_results.append(json.loads(line))
        except Exception as e:
            pass
    return search_results

# Download video
def DownloadVideo(video_url, output_file, verbose = False, exit_on_failure = False):

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
        "-o", output_file,
        "-S", "res,ext:mp4:m4a",
        "--recode", "mp4",
        video_url
    ]

    # Run download command
    code = command.RunBlockingCommand(
        cmd = download_cmd,
        options = command.CommandOptions(
            blocking_processes = [youtube_tool]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Check result
    return os.path.exists(output_file)
