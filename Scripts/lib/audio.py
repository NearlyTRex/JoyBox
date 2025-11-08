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
import audiometadata

# Get album directories for processing
def GetAlbumDirectories(genre_type = None, album_name = None, artist_name = None):

    # Get music dir
    music_dir = environment.GetLockerMusicDir(genre_type)
    if not system.IsPathDirectory(music_dir):
        return []

    # Get album dirs
    album_dirs = []
    if album_name:
        album_path = environment.GetLockerMusicAlbumDir(
            album_name = album_name,
            artist_name = artist_name,
            source_type = config.SourceType.LOCAL,
            genre_type = genre_type.value if genre_type else None)
        if system.IsPathDirectory(album_path):
            album_dirs.append(album_path)
    else:
        for item in system.GetDirectoryContents(music_dir):
            item_path = system.JoinPaths(music_dir, item)
            if system.IsPathDirectory(item_path):
                subdirs = [subitem for subitem in system.GetDirectoryContents(item_path)
                          if system.IsPathDirectory(system.JoinPaths(item_path, subitem))]
                direct_mp3_files = [f for f in system.GetDirectoryContents(item_path)
                                   if f.lower().endswith('.mp3') and system.IsPathFile(system.JoinPaths(item_path, f))]
                if subdirs and not direct_mp3_files:
                    for subdir in subdirs:
                        subdir_path = system.JoinPaths(item_path, subdir)
                        if system.IsPathDirectory(subdir_path):
                            album_dirs.append(subdir_path)
                else:
                    album_dirs.append(item_path)
    return album_dirs

# Download channel audio files
def DownloadChannelAudioFiles(channels, genre_type, cookie_source = None, verbose = False, pretend_run = False, exit_on_failure = False):

    # Download channels
    system.LogInfo(f"Starting audio download process for genre: {genre_type}")
    system.LogInfo(f"Processing {len(channels)} channels")
    for i, channel in enumerate(channels, 1):
        channel_name = channel.get("name")
        channel_url = channel.get("url")
        system.LogInfo(f"[{i}/{len(channels)}] Processing channel: {channel_name}")
        system.LogInfo(f"Channel URL: {channel_url}")

        # Create temporary directory
        system.LogInfo("Creating temporary directory...")
        tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(
            verbose = verbose,
            pretend_run = pretend_run)
        if not tmp_dir_success:
            system.LogError(f"Failed to create temporary directory for channel: {channel_name}")
            return False
        system.LogInfo(f"Created temporary directory: {tmp_dir_result}")

        # Get channel info
        channel_archive_file = environment.GetFileAudioMetadataArchiveFile(genre_type, channel_name)
        channel_music_dir = environment.GetLockerMusicAlbumDir(
            album_name = channel_name,
            source_type = config.SourceType.LOCAL,
            genre_type = genre_type)
        system.LogInfo(f"Archive file: {channel_archive_file}")
        system.LogInfo(f"Target music directory: {channel_music_dir}")

        # Download channel
        system.LogInfo("Starting video download...")
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
            system.LogError(f"Failed to download videos for channel: {channel_name}")
            return False

        # Check what was downloaded
        if system.IsPathDirectory(tmp_dir_result):
            downloaded_files = system.GetDirectoryContents(tmp_dir_result)
            audio_files = [f for f in downloaded_files if f.endswith('.mp3')]
            system.LogInfo(f"Downloaded {len(audio_files)} audio files")
            if len(audio_files) > 0:
                system.LogInfo(f"First few files: {audio_files[:3]}")
        else:
            system.LogWarning(f"Temporary directory doesn't exist after download: {tmp_dir_result}")

        # Make music dir
        system.LogInfo(f"Creating target music directory: {channel_music_dir}")
        system.MakeDirectory(
            src = channel_music_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Backup audio files only (filter out thumbnails and other non-audio files)
        system.LogInfo(f"Starting backup from {tmp_dir_result} to {channel_music_dir}")

        # Create a subdirectory for audio files only
        audio_only_dir = system.JoinPaths(tmp_dir_result, "audio_only")
        system.MakeDirectory(
            src = audio_only_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Move only audio files to the audio-only subdirectory
        if system.IsPathDirectory(tmp_dir_result):
            downloaded_files = system.GetDirectoryContents(tmp_dir_result)
            for file_name in downloaded_files:
                if file_name.lower().endswith(('.mp3', '.m4a', '.wav', '.flac', '.ogg')):
                    src_file = system.JoinPaths(tmp_dir_result, file_name)
                    dest_file = system.JoinPaths(audio_only_dir, file_name)
                    if system.IsPathFile(src_file):
                        system.MoveFileOrDirectory(
                            src = src_file,
                            dest = dest_file,
                            verbose = verbose,
                            pretend_run = pretend_run,
                            exit_on_failure = exit_on_failure)

        # Backup audio files
        backup_success = locker.BackupFiles(
            src = audio_only_dir,
            dest = channel_music_dir,
            show_progress = True,
            skip_existing = True,
            skip_identical = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if backup_success:
            system.LogInfo("Backup completed successfully")
        else:
            system.LogError("Backup process failed")
            return False

        # Delete temporary directory
        system.LogInfo(f"Cleaning up temporary directory: {tmp_dir_result}")
        cleanup_success = system.RemoveDirectory(
            src = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if cleanup_success:
            system.LogInfo("Temporary directory cleanup completed")
        else:
            system.LogWarning("Failed to clean up temporary directory")
        system.LogInfo(f"[{i}/{len(channels)}] Completed processing channel: {channel_name}")
    system.LogInfo("Audio download process completed successfully")
    return True

# Download story audio files
def DownloadStoryAudioFiles(cookie_source = None, verbose = False, pretend_run = False, exit_on_failure = False):
    return DownloadChannelAudioFiles(
        channels = config.story_channels,
        genre_type = config.AudioGenreType.STORY,
        cookie_source = cookie_source,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Download asmr audio files
def DownloadASMRAudioFiles(cookie_source = None, verbose = False, pretend_run = False, exit_on_failure = False):
    return DownloadChannelAudioFiles(
        channels = config.asmr_channels,
        genre_type = config.AudioGenreType.ASMR,
        cookie_source = cookie_source,
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
        album_name = system.GetFilenameFile(album_dir)

        # Detect artist name
        detected_artist_name = None
        parent_dir = system.GetFilenameDirectory(album_dir)
        parent_name = system.GetFilenameFile(parent_dir)
        if parent_name != genre_type.value:
            detected_artist_name = parent_name
        system.LogInfo(f"Scanning album: {album_name}" + (f" by {detected_artist_name}" if detected_artist_name else ""))

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
            system.LogError(f"Failed to extract metadata from album: {album_name}")
            return False

        # Write album metadata JSON
        json_file = environment.GetFileAudioMetadataFile(
            config.AudioMetadataType.TAG.value,
            genre_type.value if genre_type else None,
            album_name,
            detected_artist_name)
        if system.WriteJsonFile(
            src = json_file,
            json_data = album_data,
            sort_keys = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure):
            system.LogInfo(f"Generated metadata file: {json_file}")
        else:
            system.LogError(f"Failed to write metadata file: {json_file}")
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
        album_name = system.GetFilenameFile(album_dir)

        # Detect artist name
        detected_artist_name = None
        parent_dir = system.GetFilenameDirectory(album_dir)
        parent_name = system.GetFilenameFile(parent_dir)
        if parent_name != genre_type.value:
            detected_artist_name = parent_name

        # Clear album tags
        system.LogInfo(f"Clearing tags from album: {album_name}" + (f" by {detected_artist_name}" if detected_artist_name else ""))
        if audio_metadata.clear_album_tags(
            album_dir = album_dir,
            preserve_artwork = preserve_artwork,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure):
            system.LogInfo(f"Cleared tags from album: {album_name}")
        else:
            system.LogError(f"Failed to clear tags from album: {album_name}")
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
        album_name = system.GetFilenameFile(album_dir)

        # Detect artist name
        detected_artist_name = None
        parent_dir = system.GetFilenameDirectory(album_dir)
        parent_name = system.GetFilenameFile(parent_dir)
        if parent_name != genre_type.value:
            detected_artist_name = parent_name

        # Find metadata file
        json_file = environment.GetFileAudioMetadataFile(
            config.AudioMetadataType.TAG.value,
            genre_type.value if genre_type else None,
            album_name,
            detected_artist_name)
        if not system.IsPathFile(json_file):
            system.LogError(f"Metadata file not found: {json_file}")
            return False

        # Read album metadata
        album_data = system.ReadJsonFile(
            src = json_file,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not album_data:
            system.LogError(f"Failed to read metadata file: {json_file}")
            return False

        # Apply tags to album
        system.LogInfo(f"Applying tags to album: {album_name}" + (f" by {detected_artist_name}" if detected_artist_name else ""))
        if audio_metadata.set_album_tags(
            album_dir = album_dir,
            album_metadata = album_data,
            clear_existing = clear_existing,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure):
            system.LogInfo(f"Applied tags to album: {album_name}")
        else:
            system.LogError(f"Failed to apply tags to album: {album_name}")
            return False
    return True
