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

# Build audio metadata files
def BuildAudioMetadataFiles(
    genre_type = None,
    album_name = None,
    artist_name = None,
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
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not album_data:
            system.LogError(f"Failed to extract metadata from album: {album_name}")
            return False

        # Create output directory structure
        album_output_dir = environment.GetFileAudioMetadataAlbumDir(
            config.AudioMetadataType.TAG.value,
            genre_type.value if genre_type else None,
            album_name,
            detected_artist_name)
        system.MakeDirectory(
            src = album_output_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

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
