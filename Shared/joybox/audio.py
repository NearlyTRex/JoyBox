# Local imports
from joybox import config
from joybox import logger
from joybox import paths
from joybox import serialization
from joybox import environment
from joybox import fileops
from joybox import google
from joybox import locker
from joybox import audiometadata

# An artist folder's album subfolders, or the folder itself when it is an album
# (it holds mp3 files directly, or no subfolders)
def _get_item_album_dirs(item_path):
    subdirs = [subitem for subitem in paths.get_directory_contents(item_path)
              if paths.is_path_directory(paths.join_paths(item_path, subitem))]
    direct_mp3_files = [f for f in paths.get_directory_contents(item_path)
                       if f.lower().endswith('.mp3') and paths.is_path_file(paths.join_paths(item_path, f))]
    if subdirs and not direct_mp3_files:
        return [paths.join_paths(item_path, subdir) for subdir in subdirs]
    return [item_path]

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
                album_dirs += _get_item_album_dirs(item_path)
    return album_dirs

# Video ids already listed in a yt-dlp download archive; empty when it is absent or unreadable
def get_archived_video_ids(archive_file):
    ids = set()
    if archive_file and paths.is_path_file(archive_file):
        lines = serialization.read_text_lines(archive_file)
        if lines is None:
            logger.log_warning("Unable to read download archive %s, so every video counts as new" % archive_file)
        for line in lines or []:
            tokens = line.split()
            if tokens:
                ids.add(tokens[-1])
    return ids

# Whether the name has one of the collected audio extensions, in any case
def is_audio_filename(file_name):
    return file_name.lower().endswith(('.mp3', '.m4a', '.wav', '.flac', '.ogg'))

# Move the directory's top-level audio files into audio_only_dir, making it on the first move
def move_audio_files(work_dir, audio_only_dir, verbose = False, pretend_run = False, exit_on_failure = False):
    for file_name in paths.get_directory_contents(work_dir):
        if not is_audio_filename(file_name):
            continue
        src_file = paths.join_paths(work_dir, file_name)
        if not paths.is_path_file(src_file):
            continue
        if not paths.is_path_directory(audio_only_dir):
            fileops.make_directory(src = audio_only_dir, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
        fileops.move_file_or_directory(
            src = src_file,
            dest = paths.join_paths(audio_only_dir, file_name),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Collect audio files in a directory and upload them to the channel's music dir
def collect_and_upload_audio(work_dir, channel_music_dir, locker_type = None, verbose = False, pretend_run = False, exit_on_failure = False):

    # Nothing to do without a directory
    if not paths.is_path_directory(work_dir):
        return True

    # Move top-level audio into an audio-only subdirectory (filter out thumbnails,
    # etc.). The subdir may already hold files from a previous interrupted upload,
    # so we merge into it rather than treating an empty top level as "nothing to do".
    audio_only_dir = paths.join_paths(work_dir, "audio_only")
    move_audio_files(work_dir, audio_only_dir, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)

    # Upload anything pending (just-moved or left by a previous interrupted run)
    if not paths.is_path_directory(audio_only_dir):
        return True
    pending = [f for f in paths.get_directory_contents(audio_only_dir) if is_audio_filename(f)]
    if not pending:
        return True

    # Upload the collected audio
    logger.log_info(f"Backing up {len(pending)} audio file(s) to {channel_music_dir}")
    dest_rel_path = locker.convert_to_relative_path(channel_music_dir)
    backup_success = locker.backup_if_absent(
        audio_only_dir, dest_rel_path, locker_type, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
    if not backup_success:
        logger.log_error("Backup process failed")
        return False

    # Remove just the uploaded copies; the working dir itself is left for the caller
    fileops.remove_directory(src = audio_only_dir, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
    return True

# Download a batch, then collect and upload its audio. It works in the persistent directory,
# kept for resuming, when there is one, and otherwise in a temporary one.
def download_audio_batch(
    target,
    persistent_dir,
    archive_file,
    music_dir,
    cookie_source = None,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    with fileops.existing_or_temporary_directory(persistent_dir, verbose = verbose, pretend_run = pretend_run) as work_dir:
        if not work_dir:
            logger.log_error("Failed to create temporary directory for batch")
            return False
        success = google.download_video(
            video_url = target,
            audio_only = True,
            output_dir = work_dir,
            download_archive = archive_file,
            cookie_source = cookie_source,
            concurrent_fragments = getattr(config, "AUDIO_DOWNLOAD_CONCURRENT_FRAGMENTS", 1),
            sanitize_filenames = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error("Failed to download batch")
            return False
        return collect_and_upload_audio(
            work_dir, music_dir, locker_type = locker_type, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)

# The channels named channel_name, by exact then substring match ignoring case;
# None after logging the available names when nothing matches
def _select_channels(channels, channel_name, genre_type):
    query = channel_name.strip().lower()
    matches = [c for c in channels if c.get("name", "").lower() == query]
    if not matches:
        matches = [c for c in channels if query in c.get("name", "").lower()]
    if not matches:
        available = ", ".join(c.get("name", "") for c in channels)
        logger.log_error(f"No channel matching '{channel_name}' for genre {genre_type}. Available: {available}")
        return None
    return matches

# A video's download url; a YouTube watch url is rebuilt only when the enumeration gave none
def _video_target_url(vid, url):
    return url or f"https://www.youtube.com/watch?v={vid}"

# The channel's (id, url) videos and those not yet in its archive, the new ones oldest first when asked
def _get_new_channel_videos(channel_url, archive_file, oldest_first, cookie_source, verbose, pretend_run, exit_on_failure):

    # The id is used for archive matching; the url is used verbatim to build
    # download targets so non-YouTube sites work too.
    all_videos = google.get_playlist_video_ids(
        video_url = channel_url,
        cookie_source = cookie_source,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    archived_ids = get_archived_video_ids(archive_file)
    new_videos = [(vid, url) for (vid, url) in all_videos if vid not in archived_ids]

    # Channels enumerate newest-first; reverse so the oldest new videos download first
    if oldest_first:
        new_videos = list(reversed(new_videos))
        logger.log_info("Downloading oldest videos first")
    return all_videos, new_videos

# The videos' download urls in lists of batch_size, or one list when batch_size is 0
def _chunk_video_targets(new_videos, batch_size):
    if batch_size <= 0:
        return [[_video_target_url(vid, url) for (vid, url) in new_videos]]
    batch_targets = []
    for j in range(0, len(new_videos), batch_size):
        chunk = new_videos[j:j + batch_size]
        batch_targets.append([_video_target_url(vid, url) for (vid, url) in chunk])
    return batch_targets

# Download targets for a channel: the whole channel when it could not be enumerated,
# else its new videos' urls split into batches of the configured size
def _build_batch_targets(channel_url, all_videos, new_videos):
    batch_size = getattr(config, "AUDIO_DOWNLOAD_BATCH_SIZE", 0) or 0
    batch_targets = []
    if not all_videos:
        logger.log_warning("Could not enumerate channel videos; downloading whole channel in one pass")
        batch_targets = [channel_url]
    elif new_videos:
        logger.log_info(f"Channel has {len(all_videos)} videos, {len(new_videos)} new")
        batch_targets = _chunk_video_targets(new_videos, batch_size)
    else:
        logger.log_info(f"Channel up to date ({len(all_videos)} videos already archived)")
    return batch_targets

# The download targets for a channel's videos not yet in its archive file, in batches
def _get_channel_batch_targets(channel_url, archive_file, oldest_first, cookie_source, verbose, pretend_run, exit_on_failure):
    all_videos, new_videos = _get_new_channel_videos(
        channel_url, archive_file, oldest_first, cookie_source, verbose, pretend_run, exit_on_failure)
    return _build_batch_targets(channel_url, all_videos, new_videos)

# Make the channel's persistent directory and upload any audio a previous interrupted run left there
def _resume_persistent_dir(persistent_dir, channel_music_dir, locker_type, verbose, pretend_run, exit_on_failure):
    fileops.make_directory(src = persistent_dir, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
    logger.log_info(f"Resuming from persistent directory: {persistent_dir}")
    return collect_and_upload_audio(persistent_dir, channel_music_dir, locker_type = locker_type, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)

# Download and upload each batch in turn (download -> collect audio -> upload -> clean); False on the first failure
def _download_batches(batch_targets, channel_name, persistent_dir, archive_file, music_dir, cookie_source, locker_type, verbose, pretend_run, exit_on_failure):
    for b_index, target in enumerate(batch_targets, 1):
        if len(batch_targets) > 1:
            logger.log_info(f"[{channel_name}] Batch {b_index}/{len(batch_targets)}")
        success = download_audio_batch(
            target = target,
            persistent_dir = persistent_dir,
            archive_file = archive_file,
            music_dir = music_dir,
            cookie_source = cookie_source,
            locker_type = locker_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

# Download one channel's new videos as audio into its music album; False on the first failure
def _download_channel_audio(channel, genre_type, oldest_first, cookie_source, locker_type, output_path, verbose, pretend_run, exit_on_failure):
    channel_name = channel.get("name")
    channel_url = channel.get("url")
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
        if not _resume_persistent_dir(persistent_dir, channel_music_dir, locker_type, verbose, pretend_run, exit_on_failure):
            return False

    # Enumerate channel videos and build batch targets
    batch_targets = _get_channel_batch_targets(
        channel_url, channel_archive_file, oldest_first, cookie_source, verbose, pretend_run, exit_on_failure)

    # Process each batch
    return _download_batches(
        batch_targets, channel_name, persistent_dir, channel_archive_file, channel_music_dir,
        cookie_source, locker_type, verbose, pretend_run, exit_on_failure)

# Download every channel's not-yet-archived videos as audio in batches and upload them to its music album;
# channel_name narrows to one channel by exact then substring match
def download_channel_audio_files(channels, genre_type, channel_name = None, oldest_first = None, cookie_source = None, locker_type = None, output_path = None, verbose = False, pretend_run = False, exit_on_failure = False):

    # Resolve download order. oldest_first is tri-state: True/False force the order,
    # None falls back to the config default (audio_download_oldest_first).
    if oldest_first is None:
        oldest_first = getattr(config, "AUDIO_DOWNLOAD_OLDEST_FIRST", False)

    # Optionally filter to a single channel
    if channel_name:
        channels = _select_channels(channels, channel_name, genre_type)
        if channels is None:
            return False

    # Download channels
    logger.log_info(f"Starting audio download process for genre: {genre_type}")
    logger.log_info(f"Processing {len(channels)} channels")
    for i, channel in enumerate(channels, 1):
        logger.log_info(f"[{i}/{len(channels)}] Processing channel: {channel.get('name')}")
        success = _download_channel_audio(
            channel, genre_type, oldest_first, cookie_source, locker_type, output_path, verbose, pretend_run, exit_on_failure)
        if not success:
            return False
        logger.log_info(f"[{i}/{len(channels)}] Completed processing channel: {channel.get('name')}")
    logger.log_info("Audio download process completed successfully")
    return True

# Download new audio from the configured story channels into the story genre
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

# Download new audio from the configured ASMR channels into the ASMR genre
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

# Artist folder an album sits in, or None when it sits directly under its genre folder
# (always the case without a genre, where albums are found one level under each genre)
def detect_album_artist(album_dir, genre_type = None):
    parent_name = paths.get_filename_file(paths.get_filename_directory(album_dir))
    if genre_type is None or parent_name == genre_type.value:
        return None
    return parent_name

# The album's JSON tag metadata file
def get_album_metadata_file(genre_type, album_name, artist_name = None):
    return environment.get_file_audio_metadata_file(
        config.AudioMetadataType.TAG.value,
        genre_type.value if genre_type else None,
        album_name,
        artist_name)

# Write the album's tags to its JSON metadata file, logging the outcome; False on failure
def write_album_metadata_file(json_file, album_data, verbose = False, pretend_run = False, exit_on_failure = False):
    if serialization.write_json_file(
        src = json_file,
        json_data = album_data,
        sort_keys = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure):
        logger.log_info(f"Generated metadata file: {json_file}")
        return True
    logger.log_error(f"Failed to write metadata file: {json_file}")
    return False

# Read one album's tags and write them to its JSON metadata file; False on failure
def _build_album_metadata_file(
    audio_metadata, album_dir, genre_type, store_individual_artwork, exclude_comments,
    use_index_for_track_number, force_tags, verbose, pretend_run, exit_on_failure):
    album_name = paths.get_filename_file(album_dir)

    # Detect artist name
    detected_artist_name = detect_album_artist(album_dir, genre_type)
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
    json_file = get_album_metadata_file(genre_type, album_name, detected_artist_name)
    return write_album_metadata_file(json_file, album_data, verbose, pretend_run, exit_on_failure)

# Read the tags of each selected album and write them to its JSON metadata file; False on the first failure
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
        built = _build_album_metadata_file(
            audio_metadata, album_dir, genre_type, store_individual_artwork, exclude_comments,
            use_index_for_track_number, force_tags, verbose, pretend_run, exit_on_failure)
        if not built:
            return False
    return True

# Strip tags from every selected album's tracks, optionally keeping artwork; False on the first failure
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
        detected_artist_name = detect_album_artist(album_dir, genre_type)

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

# The album's JSON metadata, or None after logging that it is missing or unreadable
def read_album_metadata_file(json_file, verbose = False, exit_on_failure = False):
    if not paths.is_path_file(json_file):
        logger.log_error(f"Metadata file not found: {json_file}")
        return None
    album_data = serialization.read_json_file(
        src = json_file,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if not album_data:
        logger.log_error(f"Failed to read metadata file: {json_file}")
        return None
    return album_data

# Write one album's JSON metadata file back into its track tags; False on failure
def _apply_album_metadata_file(audio_metadata, album_dir, genre_type, clear_existing, verbose, pretend_run, exit_on_failure):
    album_name = paths.get_filename_file(album_dir)

    # Detect artist name
    detected_artist_name = detect_album_artist(album_dir, genre_type)

    # Read album metadata
    json_file = get_album_metadata_file(genre_type, album_name, detected_artist_name)
    album_data = read_album_metadata_file(json_file, verbose, exit_on_failure)
    if not album_data:
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
        return True
    logger.log_error(f"Failed to apply tags to album: {album_name}")
    return False

# Write each selected album's JSON metadata file back into its track tags; False when a file is missing or a write fails
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
        if not _apply_album_metadata_file(audio_metadata, album_dir, genre_type, clear_existing, verbose, pretend_run, exit_on_failure):
            return False
    return True

###########################################################
# Metadata actions
###########################################################

# Keyword options shared by the album metadata functions: which albums, and how to run
def _album_selection(genre_type, album_name, artist_name, verbose, pretend_run, exit_on_failure):
    return {
        "genre_type": genre_type,
        "album_name": album_name,
        "artist_name": artist_name,
        "verbose": verbose,
        "pretend_run": pretend_run,
        "exit_on_failure": exit_on_failure,
    }

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

    # Options every action takes
    selection = _album_selection(genre_type, album_name, artist_name, verbose, pretend_run, exit_on_failure)

    # Run the action
    if action == config.AudioMetadataAction.TAG:
        return build_audio_metadata_files(
            exclude_comments = exclude_comments,
            use_index_for_track_number = use_index_for_track_number,
            force_tags = force_tags,
            **selection)
    if action == config.AudioMetadataAction.CLEAR:
        return clear_audio_metadata_tags(preserve_artwork = preserve_artwork, **selection)
    if action == config.AudioMetadataAction.APPLY:
        return apply_audio_metadata_tags(clear_existing = clear_existing, **selection)
    logger.log_error(f"Unknown action: {action}")
    return False

# (force_tags, use_index_for_track_number) for a genre. Universal policy: comments excluded,
# genre forced to the genre folder. Per-genre: renumber tracks by index for YouTube-sourced genres.
def get_genre_tag_policy(genre_type, extra_force_tags = None):
    force_tags = { "genre": genre_type.value }
    force_tags.update(extra_force_tags or {})
    use_index_for_track_number = genre_type.value in config.audio_track_index_genres
    return force_tags, use_index_for_track_number

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

    # Universal and per-genre policy
    force_tags, use_index_for_track_number = get_genre_tag_policy(genre_type, extra_force_tags)
    logger.log_info(
        f"Tagging genre: {genre_type.value}"
        + (" (renumbering tracks by index)" if use_index_for_track_number else ""))

    # Options both steps take
    selection = _album_selection(genre_type, album_name, artist_name, verbose, pretend_run, exit_on_failure)

    # Build the metadata files (reads existing tags, writes JSON sidecars)
    if not build_audio_metadata_files(
        exclude_comments = True,
        use_index_for_track_number = use_index_for_track_number,
        force_tags = force_tags,
        **selection):
        return False

    # Apply the metadata files back to the audio files
    if not apply_tags:
        return True
    return apply_audio_metadata_tags(clear_existing = clear_existing, **selection)

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

###########################################################

# The download order the flags ask for: newest first wins when both are given, and None means
# the configured default
def _resolve_download_order(oldest_first, newest_first):
    if newest_first:
        return False
    if oldest_first:
        return True
    return None

# Download new audio for the Story or ASMR genre, logging an error when it fails; True for any
# other genre, which downloads nothing
def download_genre_audio_files(
    genre_type,
    channel_name = None,
    oldest_first = False,
    newest_first = False,
    cookie_source = None,
    locker_type = None,
    output_path = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if genre_type == config.AudioGenreType.STORY:
        download_function, genre_label = download_story_audio_files, "Story"
    elif genre_type == config.AudioGenreType.ASMR:
        download_function, genre_label = download_asmr_audio_files, "ASMR"
    else:
        return True
    success = download_function(
        channel_name = channel_name,
        oldest_first = _resolve_download_order(oldest_first, newest_first),
        cookie_source = cookie_source,
        locker_type = locker_type,
        output_path = output_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("%s audio download failed" % genre_label)
    return success

# The forced tag overrides parsed from the field=value entries for TAG, None when one is
# invalid; None for every other action
def _get_action_force_tags(action, set_values):
    if action != config.AudioMetadataAction.TAG:
        return None
    return audiometadata.parse_force_tags(set_values)

# Run a metadata action on one genre, or on every genre with albums when genre_type is None;
# set_values are the field=value tag overrides, used by TAG only. False on a bad override
def run_metadata_action_for_genres(
    action,
    genre_type = None,
    album_name = None,
    artist_name = None,
    set_values = None,
    exclude_comments = False,
    use_index_for_track_number = False,
    preserve_artwork = False,
    clear_existing = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Resolve forced tag overrides (TAG only)
    force_tags = _get_action_force_tags(action, set_values)
    if action == config.AudioMetadataAction.TAG and force_tags is None:
        return False

    # Run the selected action for one genre
    def run_for_genre(genre_type):
        return run_metadata_action(
            action = action,
            genre_type = genre_type,
            album_name = album_name,
            artist_name = artist_name,
            exclude_comments = exclude_comments,
            use_index_for_track_number = use_index_for_track_number,
            preserve_artwork = preserve_artwork,
            clear_existing = clear_existing,
            force_tags = force_tags,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Single genre, else all genres
    if genre_type is not None:
        return run_for_genre(genre_type)
    return process_all_genres(run_for_genre, album_name, artist_name)
