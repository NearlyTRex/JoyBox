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
def GetSearchResults(search_terms, num_results = 10, sort_by_duration = False, verbose = False, exit_on_failure = False):

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
def DownloadVideo(video_url, output_file = None, verbose = False, exit_on_failure = False):

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
        "-S", "res,ext:mp4:m4a",
        "--recode", "mp4",
        video_url
    ]
    if system.IsPathValid(output_file):
        download_cmd += [
            "-o", output_file,
        ]

    # Run download command
    code = command.RunBlockingCommand(
        cmd = download_cmd,
        options = command.CommandOptions(
            blocking_processes = [youtube_tool]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    return (code == 0)
