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
def download_channel_audio_files(channels, genre_type, channel_name = None, oldest_first = None, cookie_source = None, locker_type = None, output_path = None, verbose = False, pretend_run = False, exit_on_failure = False):

    # Resolve download order. oldest_first is tri-state: True/False force the order,
    # None falls back to the config default (audio_download_oldest_first).
    if oldest_first is None:
        oldest_first = getattr(config, "audio_download_oldest_first", False)

    # Optionally filter to a single channel (case-insensitive; matches exact name
    # first, then falls back to a substring match)
    if channel_name:
        query = channel_name.strip().lower()
        matches = [c for c in channels if c.get("name", "").lower() == query]
        if not matches:
            matches = [c for c in channels if query in c.get("name", "").lower()]
        if not matches:
            available = ", ".join(c.get("name", "") for c in channels)
            logger.log_error(f"No channel matching '{channel_name}' for genre {genre_type}. Available: {available}")
            return False
        channels = matches

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

        # Enumerate channel videos (as (id, url) pairs) and skip the ones already
        # downloaded (per the archive). The id is used for archive matching; the url
        # is used verbatim to build download targets so non-YouTube sites work too.
        all_videos = google.get_playlist_video_ids(
            video_url = channel_url,
            cookie_source = cookie_source,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        archived_ids = get_archived_video_ids(channel_archive_file)
        new_videos = [(vid, url) for (vid, url) in all_videos if vid not in archived_ids]

        # Channels enumerate newest-first; reverse so the oldest new videos download first
        if oldest_first:
            new_videos = list(reversed(new_videos))
            logger.log_info("Downloading oldest videos first")

        # Resolve a video's download url; fall back to reconstructing a YouTube watch
        # url only if the enumeration did not yield one (keeps prior behavior)
        def video_target_url(vid, url):
            return url or f"https://www.youtube.com/watch?v={vid}"

        # Build batch targets (each target is downloaded + uploaded in turn)
        batch_size = getattr(config, "audio_download_batch_size", 0) or 0
        batch_targets = []
        if not all_videos:
            logger.log_warning("Could not enumerate channel videos; downloading whole channel in one pass")
            batch_targets = [channel_url]
        elif new_videos:
            logger.log_info(f"Channel has {len(all_videos)} videos, {len(new_videos)} new")
            if batch_size > 0:
                for j in range(0, len(new_videos), batch_size):
                    chunk = new_videos[j:j + batch_size]
                    batch_targets.append([video_target_url(vid, url) for (vid, url) in chunk])
            else:
                batch_targets = [[video_target_url(vid, url) for (vid, url) in new_videos]]
        else:
            logger.log_info(f"Channel up to date ({len(all_videos)} videos already archived)")

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
                concurrent_fragments = getattr(config, "audio_download_concurrent_fragments", 1),
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
def download_story_audio_files(channel_name = None, oldest_first = None, cookie_source = None, locker_type = None, output_path = None, verbose = False, pretend_run = False, exit_on_failure = False):
    return download_channel_audio_files(
        channels = config.story_channels,
        genre_type = config.AudioGenreType.STORY,
        channel_name = channel_name,
        oldest_first = oldest_first,
        cookie_source = cookie_source,
        locker_type = locker_type,
        output_path = output_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Download asmr audio files
def download_asmr_audio_files(channel_name = None, oldest_first = None, cookie_source = None, locker_type = None, output_path = None, verbose = False, pretend_run = False, exit_on_failure = False):
    return download_channel_audio_files(
        channels = config.asmr_channels,
        genre_type = config.AudioGenreType.ASMR,
        channel_name = channel_name,
        oldest_first = oldest_first,
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
    force_tags = None,
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
            force_tags = force_tags,
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

###########################################################
# Metadata actions
###########################################################

# Run a single metadata action for one genre
def run_metadata_action(
    action,
    genre_type,
    album_name = None,
    artist_name = None,
    exclude_comments = False,
    use_index_for_track_number = False,
    preserve_artwork = False,
    clear_existing = False,
    force_tags = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if action == config.AudioMetadataAction.TAG:
        return build_audio_metadata_files(
            genre_type = genre_type,
            album_name = album_name,
            artist_name = artist_name,
            exclude_comments = exclude_comments,
            use_index_for_track_number = use_index_for_track_number,
            force_tags = force_tags,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    elif action == config.AudioMetadataAction.CLEAR:
        return clear_audio_metadata_tags(
            genre_type = genre_type,
            album_name = album_name,
            artist_name = artist_name,
            preserve_artwork = preserve_artwork,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    elif action == config.AudioMetadataAction.APPLY:
        return apply_audio_metadata_tags(
            genre_type = genre_type,
            album_name = album_name,
            artist_name = artist_name,
            clear_existing = clear_existing,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    else:
        logger.log_error(f"Unknown action: {action}")
        return False

# Tag one genre using the universal and per-genre policies
def tag_genre_with_policy(
    genre_type,
    album_name = None,
    artist_name = None,
    extra_force_tags = None,
    apply_tags = True,
    clear_existing = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Nothing to do for a genre with no albums (not a failure)
    if not get_album_directories(genre_type, album_name, artist_name):
        logger.log_warning(f"No albums found for genre: {genre_type.value}")
        return True

    # Universal policy: comments excluded, genre forced to the genre folder
    force_tags = { "genre": genre_type.value }
    force_tags.update(extra_force_tags or {})

    # Per-genre policy: renumber tracks by index for YouTube-sourced genres
    use_index_for_track_number = genre_type.value in config.audio_track_index_genres

    logger.log_info(
        f"Tagging genre: {genre_type.value}"
        + (" (renumbering tracks by index)" if use_index_for_track_number else ""))

    # Build the metadata files (reads existing tags, writes JSON sidecars)
    if not build_audio_metadata_files(
        genre_type = genre_type,
        album_name = album_name,
        artist_name = artist_name,
        exclude_comments = True,
        use_index_for_track_number = use_index_for_track_number,
        force_tags = force_tags,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure):
        return False

    # Apply the metadata files back to the audio files
    if not apply_tags:
        return True
    return apply_audio_metadata_tags(
        genre_type = genre_type,
        album_name = album_name,
        artist_name = artist_name,
        clear_existing = clear_existing,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Run a per-genre handler across every genre that has albums
def process_all_genres(handler, album_name = None, artist_name = None):
    overall = True
    processed = 0
    for genre_type in config.AudioGenreType.members():
        if not get_album_directories(genre_type, album_name, artist_name):
            continue
        processed += 1
        logger.log_info(f"Processing genre: {genre_type.value}")
        if not handler(genre_type):
            overall = False
    if processed == 0:
        logger.log_error("No albums found in any genre")
        return False
    return overall
