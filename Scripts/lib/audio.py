# Imports
import os
import sys
import json

# Local imports
import config
import system
import logger
import paths
import serialization
import environment
import fileops
import google
import locker
import audiometadata

# Get album directories for processing
def GetAlbumDirectories(genre_type = None, album_name = None, artist_name = None):

    # Get music dir
    music_dir = environment.GetLockerMusicDir(genre_type)
    if not paths.is_path_directory(music_dir):
        return []

    # Get album dirs
    album_dirs = []
    if album_name:
        album_path = environment.GetLockerMusicAlbumDir(
            album_name = album_name,
            artist_name = artist_name,
            source_type = config.SourceType.LOCAL,
            genre_type = genre_type.value if genre_type else None)
        if paths.is_path_directory(album_path):
            album_dirs.append(album_path)
    else:
        for item in paths.get_directory_contents(music_dir):
            item_path = paths.join_paths(music_dir, item)
            if paths.is_path_directory(item_path):
                subdirs = [subitem for subitem in paths.get_directory_contents(item_path)
                          if paths.is_path_directory(paths.join_paths(item_path, subitem))]
                direct_mp3_files = [f for f in paths.get_directory_contents(item_path)
                                   if f.lower().endswith('.mp3') and paths.is_path_file(paths.join_paths(item_path, f))]
                if subdirs and not direct_mp3_files:
                    for subdir in subdirs:
                        subdir_path = paths.join_paths(item_path, subdir)
                        if paths.is_path_directory(subdir_path):
                            album_dirs.append(subdir_path)
                else:
                    album_dirs.append(item_path)
    return album_dirs

# Download channel audio files
def DownloadChannelAudioFiles(channels, genre_type, cookie_source = None, locker_type = None, verbose = False, pretend_run = False, exit_on_failure = False):

    # Download channels
    logger.log_info(f"Starting audio download process for genre: {genre_type}")
    logger.log_info(f"Processing {len(channels)} channels")
    for i, channel in enumerate(channels, 1):
        channel_name = channel.get("name")
        channel_url = channel.get("url")
        logger.log_info(f"[{i}/{len(channels)}] Processing channel: {channel_name}")
        logger.log_info(f"Channel URL: {channel_url}")

        # Create temporary directory
        logger.log_info("Creating temporary directory...")
        tmp_dir_success, tmp_dir_result = fileops.create_temporary_directory(
            verbose = verbose,
            pretend_run = pretend_run)
        if not tmp_dir_success:
            logger.log_error(f"Failed to create temporary directory for channel: {channel_name}")
            return False
        logger.log_info(f"Created temporary directory: {tmp_dir_result}")

        # Get channel info
        channel_archive_file = environment.GetFileAudioMetadataArchiveFile(genre_type, channel_name)
        channel_music_dir = environment.GetLockerMusicAlbumDir(
            album_name = channel_name,
            source_type = config.SourceType.LOCAL,
            genre_type = genre_type)
        logger.log_info(f"Archive file: {channel_archive_file}")
        logger.log_info(f"Target music directory: {channel_music_dir}")

        # Download channel
        logger.log_info("Starting video download...")
        success = google.DownloadVideo(
            video_url = channel_url,
            audio_only = True,
            output_dir = tmp_dir_result,
            download_archive = channel_archive_file,
            cookie_source = cookie_source,
            sanitize_filenames = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error(f"Failed to download videos for channel: {channel_name}")
            return False

        # Check what was downloaded
        if paths.is_path_directory(tmp_dir_result):
            downloaded_files = paths.get_directory_contents(tmp_dir_result)
            audio_files = [f for f in downloaded_files if f.endswith('.mp3')]
            logger.log_info(f"Downloaded {len(audio_files)} audio files")
            if len(audio_files) > 0:
                logger.log_info(f"First few files: {audio_files[:3]}")
        else:
            logger.log_warning(f"Temporary directory doesn't exist after download: {tmp_dir_result}")

        # Make music dir
        logger.log_info(f"Creating target music directory: {channel_music_dir}")
        fileops.make_directory(
            src = channel_music_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Backup audio files only (filter out thumbnails and other non-audio files)
        logger.log_info(f"Starting backup from {tmp_dir_result} to {channel_music_dir}")

        # Create a subdirectory for audio files only
        audio_only_dir = paths.join_paths(tmp_dir_result, "audio_only")
        fileops.make_directory(
            src = audio_only_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Move only audio files to the audio-only subdirectory
        if paths.is_path_directory(tmp_dir_result):
            downloaded_files = paths.get_directory_contents(tmp_dir_result)
            for file_name in downloaded_files:
                if file_name.lower().endswith(('.mp3', '.m4a', '.wav', '.flac', '.ogg')):
                    src_file = paths.join_paths(tmp_dir_result, file_name)
                    dest_file = paths.join_paths(audio_only_dir, file_name)
                    if paths.is_path_file(src_file):
                        fileops.move_file_or_directory(
                            src = src_file,
                            dest = dest_file,
                            verbose = verbose,
                            pretend_run = pretend_run,
                            exit_on_failure = exit_on_failure)

        # Backup audio files
        backup_success = locker.BackupFiles(
            src = audio_only_dir,
            dest = channel_music_dir,
            locker_type = locker_type,
            show_progress = True,
            skip_existing = True,
            skip_identical = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if backup_success:
            logger.log_info("Backup completed successfully")
        else:
            logger.log_error("Backup process failed")
            return False

        # Delete temporary directory
        logger.log_info(f"Cleaning up temporary directory: {tmp_dir_result}")
        cleanup_success = fileops.remove_directory(
            src = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if cleanup_success:
            logger.log_info("Temporary directory cleanup completed")
        else:
            logger.log_warning("Failed to clean up temporary directory")
        logger.log_info(f"[{i}/{len(channels)}] Completed processing channel: {channel_name}")
    logger.log_info("Audio download process completed successfully")
    return True

# Download story audio files
def DownloadStoryAudioFiles(cookie_source = None, locker_type = None, verbose = False, pretend_run = False, exit_on_failure = False):
    return DownloadChannelAudioFiles(
        channels = config.story_channels,
        genre_type = config.AudioGenreType.STORY,
        cookie_source = cookie_source,
        locker_type = locker_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Download asmr audio files
def DownloadASMRAudioFiles(cookie_source = None, locker_type = None, verbose = False, pretend_run = False, exit_on_failure = False):
    return DownloadChannelAudioFiles(
        channels = config.asmr_channels,
        genre_type = config.AudioGenreType.ASMR,
        cookie_source = cookie_source,
        locker_type = locker_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Build audio metadata files
def BuildAudioMetadataFiles(
    genre_type = None,
    album_name = None,
    artist_name = None,
    store_individual_artwork = False,
    exclude_comments = False,
    use_index_for_track_number = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create audio metadata handler
    audio_metadata = audiometadata.AudioMetadata()

    # Get album directories
    album_dirs = GetAlbumDirectories(genre_type, album_name, artist_name)
    if not album_dirs:
        return False

    # Process each album
    for album_dir in sorted(album_dirs):
        album_name = paths.get_filename_file(album_dir)

        # Detect artist name
        detected_artist_name = None
        parent_dir = paths.get_filename_directory(album_dir)
        parent_name = paths.get_filename_file(parent_dir)
        if parent_name != genre_type.value:
            detected_artist_name = parent_name
        logger.log_info(f"Scanning album: {album_name}" + (f" by {detected_artist_name}" if detected_artist_name else ""))

        # Extract album metadata
        album_data = audio_metadata.get_album_tags(
            album_dir = album_dir,
            genre_type = genre_type,
            store_individual_artwork = store_individual_artwork,
            exclude_comments = exclude_comments,
            use_index_for_track_number = use_index_for_track_number,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not album_data:
            logger.log_error(f"Failed to extract metadata from album: {album_name}")
            return False

        # Write album metadata JSON
        json_file = environment.GetFileAudioMetadataFile(
            config.AudioMetadataType.TAG.value,
            genre_type.value if genre_type else None,
            album_name,
            detected_artist_name)
        if serialization.write_json_file(
            src = json_file,
            json_data = album_data,
            sort_keys = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure):
            logger.log_info(f"Generated metadata file: {json_file}")
        else:
            logger.log_error(f"Failed to write metadata file: {json_file}")
            return False
    return True

# Clear audio metadata tags
def ClearAudioMetadataTags(
    genre_type = None,
    album_name = None,
    artist_name = None,
    preserve_artwork = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create audio metadata handler
    audio_metadata = audiometadata.AudioMetadata()

    # Get album directories
    album_dirs = GetAlbumDirectories(genre_type, album_name, artist_name)
    if not album_dirs:
        return False

    # Process each album
    for album_dir in sorted(album_dirs):
        album_name = paths.get_filename_file(album_dir)

        # Detect artist name
        detected_artist_name = None
        parent_dir = paths.get_filename_directory(album_dir)
        parent_name = paths.get_filename_file(parent_dir)
        if parent_name != genre_type.value:
            detected_artist_name = parent_name

        # Clear album tags
        logger.log_info(f"Clearing tags from album: {album_name}" + (f" by {detected_artist_name}" if detected_artist_name else ""))
        if audio_metadata.clear_album_tags(
            album_dir = album_dir,
            preserve_artwork = preserve_artwork,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure):
            logger.log_info(f"Cleared tags from album: {album_name}")
        else:
            logger.log_error(f"Failed to clear tags from album: {album_name}")
            return False
    return True

# Apply audio metadata tags
def ApplyAudioMetadataTags(
    genre_type = None,
    album_name = None,
    artist_name = None,
    clear_existing = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create audio metadata handler
    audio_metadata = audiometadata.AudioMetadata()

    # Get album directories
    album_dirs = GetAlbumDirectories(genre_type, album_name, artist_name)
    if not album_dirs:
        return False

    # Process each album
    for album_dir in sorted(album_dirs):
        album_name = paths.get_filename_file(album_dir)

        # Detect artist name
        detected_artist_name = None
        parent_dir = paths.get_filename_directory(album_dir)
        parent_name = paths.get_filename_file(parent_dir)
        if parent_name != genre_type.value:
            detected_artist_name = parent_name

        # Find metadata file
        json_file = environment.GetFileAudioMetadataFile(
            config.AudioMetadataType.TAG.value,
            genre_type.value if genre_type else None,
            album_name,
            detected_artist_name)
        if not paths.is_path_file(json_file):
            logger.log_error(f"Metadata file not found: {json_file}")
            return False

        # Read album metadata
        album_data = serialization.read_json_file(
            src = json_file,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not album_data:
            logger.log_error(f"Failed to read metadata file: {json_file}")
            return False

        # Apply tags to album
        logger.log_info(f"Applying tags to album: {album_name}" + (f" by {detected_artist_name}" if detected_artist_name else ""))
        if audio_metadata.set_album_tags(
            album_dir = album_dir,
            album_metadata = album_data,
            clear_existing = clear_existing,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure):
            logger.log_info(f"Applied tags to album: {album_name}")
        else:
            logger.log_error(f"Failed to apply tags to album: {album_name}")
            return False
    return True
