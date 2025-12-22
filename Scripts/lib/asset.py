# Imports
import os, os.path
import sys

# Local imports
import config
import system
import logger
import command
import programs
import network
import image
import google

# Clean exif data
def CleanExifData(
    asset_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    exif_tool = None
    if programs.IsToolInstalled("ExifTool"):
        exif_tool = programs.GetToolProgram("ExifTool")
    if not exif_tool:
        logger.log_error("ExifTool was not found")
        return False

    # Get clean command
    clean_cmd = [
        exif_tool,
        "-overwrite_original",
        "-All=",
        "-r",
        asset_file
    ]

    # Run clean command
    code = command.RunReturncodeCommand(
        cmd = clean_cmd,
        options = command.CreateCommandOptions(
            blocking_processes = [exif_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return (code == 0)

# Download asset
def DownloadAsset(
    asset_url,
    asset_file,
    asset_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Video
    if asset_type == config.AssetType.VIDEO:

        # YouTube
        if asset_url.startswith("https://www.youtube.com"):
            success = google.DownloadVideo(
                video_url = asset_url,
                output_file = asset_file,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            return success

    # Download file by default
    success = network.DownloadUrl(
        url = asset_url,
        output_file = asset_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Clean asset
def CleanAsset(
    asset_file,
    asset_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Clean exif data
    success = CleanExifData(
        asset_file = asset_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Should be successful
    return True

# Convert asset
def ConvertAsset(
    asset_src,
    asset_dest,
    asset_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Image assets
    if asset_type in config.AssetImageType.members():
        success = image.ConvertImageToJPEG(
            image_src = asset_src,
            image_dest = asset_dest,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

    # Transfer file by default
    success = system.SmartTransfer(
        src = asset_src,
        dest = asset_dest,
        skip_existing = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success
