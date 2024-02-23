# Imports
import os, os.path
import sys

# Local imports
import command
import archive
import programs
import system

# Download game
def DownloadGame(appid, branchid, output_dir, platform, arch, login, verbose = False, exit_on_failure = False):

    # Get tool
    steam_tool = None
    if programs.IsToolInstalled("SteamDepotDownloader"):
        steam_tool = programs.GetToolProgram("SteamDepotDownloader")
    if not steam_tool:
        system.LogError("SteamDepotDownloader was not found")
        sys.exit(1)

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(verbose = verbose)
    if not tmp_dir_success:
        return False

    # Get download command
    download_cmd = [
        steam_tool,
        "-app", appid,
        "-os", platform,
        "-osarch", arch,
        "-dir", tmp_dir_result
    ]
    if branchid:
        download_cmd += [
            "-beta", branchid
        ]
    if login:
        download_cmd += [
            "-username", login,
            "-remember-password"
        ]

    # Run download command
    command.RunCheckedCommand(
        cmd = download_cmd,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Get archive name
    archive_name = "%s.7z" % appid
    if branchid:
        archive_name = "%s-%s.7z" % (appid, branchid)

    # Archive downloaded files
    success = archive.CreateArchiveFromFolder(
        archive_file = os.path.join(output_dir, archive_name),
        source_dir = tmp_dir_result,
        excludes = [".DepotDownloader"],
        volume_size = "4092m",
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Delete temporary directory
    system.RemoveDirectory(tmp_dir_result, verbose = verbose)

    # Check result
    return os.path.exists(output_dir)
