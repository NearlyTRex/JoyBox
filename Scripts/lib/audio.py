# Imports
import os
import sys
import json

# Local imports
import config
import system
import environment
import google
import locker

# Download channel audio files
def DownloadChannelAudioFiles(channels, genre_type, verbose = False, pretend_run = False, exit_on_failure = False):

    # Download channels
    for channel in channels:

        # Create temporary directory
        tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(
            verbose = verbose,
            pretend_run = pretend_run)
        if not tmp_dir_success:
            return False

        # Get channel info
        channel_name = channel.get("name")
        channel_url = channel.get("url")
        channel_archive_file = environment.GetFileAudioMetadataArchiveFile(genre_type, channel_name)
        channel_music_dir = environment.GetLockerMusicAlbumDir(
            album_name = channel_name,
            source_type = config.SourceType.LOCAL,
            genre_type = genre_type)

        # Download channel
        success = google.DownloadVideo(
            video_url = channel_url,
            audio_only = True,
            output_dir = tmp_dir_result,
            download_archive = channel_archive_file,
            sanitize_filenames = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

        # Make music dir
        system.MakeDirectory(
            src = channel_music_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Backup audio files
        locker.BackupFiles(
            src = tmp_dir_result,
            dest = channel_music_dir,
            show_progress = True,
            skip_existing = True,
            skip_identical = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Delete temporary directory
        system.RemoveDirectory(
            src = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return True

# Download story audio files
def DownloadStoryAudioFiles(verbose = False, pretend_run = False, exit_on_failure = False):
    return DownloadChannelAudioFiles(
        channels = config.story_channels,
        genre_type = config.AudioGenreType.STORY,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Download asmr audio files
def DownloadASMRAudioFiles(verbose = False, pretend_run = False, exit_on_failure = False):
    return DownloadChannelAudioFiles(
        channels = config.asmr_channels,
        genre_type = config.AudioGenreType.ASMR,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
