# Local imports
import joybox.config as config
import joybox.logger as logger
import joybox.paths as paths
import joybox.serialization as serialization
import joybox.environment as environment
import joybox.fileops as fileops
import joybox.google as google
import joybox.locker as locker
import joybox.audiometadata as audiometadata

# Get album directories for processing
def get_album_directories(genre_type = None, album_name = None, artist_name = None):

    # Get music dir
    music_dir = environment.get_locker_music_dir(genre_type)
    if not paths.is_path_directory(music_dir):
        return []

    # Get album dirs
    album_dirs = []
    if album_name:
        album_path = environment.get_locker_music_album_dir(
            album_name = album_name,
            artist_name = artist_name,
            locker_type = config.LockerType.LOCAL,
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

# Get archived video ids
def get_archived_video_ids(archive_file):
    ids = set()
    if archive_file and paths.is_path_file(archive_file):
        try:
            with open(archive_file, "r", encoding = "utf-8") as f:
                for line in f:
                    tokens = line.split()
                    if tokens:
                        ids.add(tokens[-1])
        except Exception:
            pass
    return ids

# Collect audio files in a directory and upload them to the channel's music dir
def collect_and_upload_audio(work_dir, channel_music_dir, locker_type = None, verbose = False, pretend_run = False, exit_on_failure = False):

    # Nothing to do without a directory
    if not paths.is_path_directory(work_dir):
        return True

    # Move top-level audio into an audio-only subdirectory (filter out thumbnails,
    # etc.). The subdir may already hold files from a previous interrupted upload,
    # so we merge into it rather than treating an empty top level as "nothing to do".
    audio_only_dir = paths.join_paths(work_dir, "audio_only")
    for file_name in paths.get_directory_contents(work_dir):
        if file_name.lower().endswith(('.mp3', '.m4a', '.wav', '.flac', '.ogg')):
            src_file = paths.join_paths(work_dir, file_name)
            if paths.is_path_file(src_file):
                if not paths.is_path_directory(audio_only_dir):
                    fileops.make_directory(src = audio_only_dir, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
                fileops.move_file_or_directory(
                    src = src_file,
                    dest = paths.join_paths(audio_only_dir, file_name),
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)

    # Upload anything pending (just-moved or left by a previous interrupted run)
    if not paths.is_path_directory(audio_only_dir):
        return True
    pending = [f for f in paths.get_directory_contents(audio_only_dir)
               if f.lower().endswith(('.mp3', '.m4a', '.wav', '.flac', '.ogg'))]
    if not pending:
        return True

    # Upload the collected audio
    logger.log_info(f"Backing up {len(pending)} audio file(s) to {channel_music_dir}")
    dest_rel_path = locker.convert_to_relative_path(channel_music_dir)
    backup_success = locker.backup(
        src = audio_only_dir,
        dest_rel_path = dest_rel_path,
        locker_type = locker_type,
        show_progress = True,
        skip_existing = True,
        skip_identical = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not backup_success:
        logger.log_error("Backup process failed")
        return False

    # Remove just the uploaded copies; the working dir itself is left for the caller
    fileops.remove_directory(src = audio_only_dir, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
    return True

# Download channel audio files
def download_channel_audio_files(channels, genre_type, cookie_source = None, locker_type = None, output_path = None, verbose = False, pretend_run = False, exit_on_failure = False):

    # Download channels
    logger.log_info(f"Starting audio download process for genre: {genre_type}")
    logger.log_info(f"Processing {len(channels)} channels")
    for i, channel in enumerate(channels, 1):
        channel_name = channel.get("name")
        channel_url = channel.get("url")
        logger.log_info(f"[{i}/{len(channels)}] Processing channel: {channel_name}")
        logger.log_info(f"Channel URL: {channel_url}")

        # Channel paths
        channel_archive_file = environment.get_file_audio_metadata_archive_file(genre_type, channel_name)
        channel_music_dir = environment.get_locker_music_album_dir(
            album_name = channel_name,
            locker_type = config.LockerType.LOCAL,
            genre_type = genre_type)
        logger.log_info(f"Archive file: {channel_archive_file}")
        logger.log_info(f"Target music directory: {channel_music_dir}")

        # Make target music dir
        fileops.make_directory(
            src = channel_music_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Resolve the working directory. With an output path it is persistent and
        # resumable (per channel); otherwise each batch uses a throwaway temp dir.
        persistent_dir = None
        if output_path:
            persistent_dir = paths.join_paths(output_path, channel_name)
            fileops.make_directory(src = persistent_dir, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
            # Recover/upload any audio left here by a previous interrupted run
            logger.log_info(f"Resuming from persistent directory: {persistent_dir}")
            if not collect_and_upload_audio(persistent_dir, channel_music_dir, locker_type = locker_type, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure):
                return False

        # Enumerate channel videos and skip the ones already downloaded (per the archive)
        all_video_ids = google.get_playlist_video_ids(
            video_url = channel_url,
            cookie_source = cookie_source,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        archived_ids = get_archived_video_ids(channel_archive_file)
        new_video_ids = [vid for vid in all_video_ids if vid not in archived_ids]

        # Build batch targets (each target is downloaded + uploaded in turn)
        batch_size = getattr(config, "audio_download_batch_size", 0) or 0
        batch_targets = []
        if not all_video_ids:
            logger.log_warning("Could not enumerate channel videos; downloading whole channel in one pass")
            batch_targets = [channel_url]
        elif new_video_ids:
            logger.log_info(f"Channel has {len(all_video_ids)} videos, {len(new_video_ids)} new")
            if batch_size > 0:
                for j in range(0, len(new_video_ids), batch_size):
                    chunk = new_video_ids[j:j + batch_size]
                    batch_targets.append([f"https://www.youtube.com/watch?v={vid}" for vid in chunk])
            else:
                batch_targets = [[f"https://www.youtube.com/watch?v={vid}" for vid in new_video_ids]]
        else:
            logger.log_info(f"Channel up to date ({len(all_video_ids)} videos already archived)")

        # Process each batch: download -> collect audio -> upload -> clean
        for b_index, target in enumerate(batch_targets, 1):
            if len(batch_targets) > 1:
                logger.log_info(f"[{channel_name}] Batch {b_index}/{len(batch_targets)}")

            # Working dir for this batch (persistent dir is reused and kept)
            if persistent_dir:
                work_dir = persistent_dir
            else:
                tmp_dir_success, work_dir = fileops.create_temporary_directory(verbose = verbose, pretend_run = pretend_run)
                if not tmp_dir_success:
                    logger.log_error("Failed to create temporary directory for batch")
                    return False

            # Download the batch
            success = google.download_video(
                video_url = target,
                audio_only = True,
                output_dir = work_dir,
                download_archive = channel_archive_file,
                cookie_source = cookie_source,
                sanitize_filenames = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                logger.log_error("Failed to download batch")
                if not persistent_dir:
                    fileops.remove_directory(src = work_dir, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
                return False

            # Collect + upload this batch right away
            if not collect_and_upload_audio(work_dir, channel_music_dir, locker_type = locker_type, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure):
                if not persistent_dir:
                    fileops.remove_directory(src = work_dir, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
                return False

            # Clean up throwaway working dir (a persistent dir is kept for resume)
            if not persistent_dir:
                fileops.remove_directory(src = work_dir, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
        logger.log_info(f"[{i}/{len(channels)}] Completed processing channel: {channel_name}")
    logger.log_info("Audio download process completed successfully")
    return True

# Download story audio files
def download_story_audio_files(cookie_source = None, locker_type = None, output_path = None, verbose = False, pretend_run = False, exit_on_failure = False):
    return download_channel_audio_files(
        channels = config.story_channels,
        genre_type = config.AudioGenreType.STORY,
        cookie_source = cookie_source,
        locker_type = locker_type,
        output_path = output_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Download asmr audio files
def download_asmr_audio_files(cookie_source = None, locker_type = None, output_path = None, verbose = False, pretend_run = False, exit_on_failure = False):
    return download_channel_audio_files(
        channels = config.asmr_channels,
        genre_type = config.AudioGenreType.ASMR,
        cookie_source = cookie_source,
        locker_type = locker_type,
        output_path = output_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Build audio metadata files
def build_audio_metadata_files(
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
    album_dirs = get_album_directories(genre_type, album_name, artist_name)
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
        json_file = environment.get_file_audio_metadata_file(
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
def clear_audio_metadata_tags(
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
    album_dirs = get_album_directories(genre_type, album_name, artist_name)
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
def apply_audio_metadata_tags(
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
    album_dirs = get_album_directories(genre_type, album_name, artist_name)
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
        json_file = environment.get_file_audio_metadata_file(
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
