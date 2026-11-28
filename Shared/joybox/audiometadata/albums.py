# Local imports
from joybox.audiometadata.audiofile import build_audio_file_info, load_audio_file
from joybox import logger
from joybox import hashutil
from joybox import paths

# The track's own artwork (kept only when individual artwork is stored and it differs
# from the album's), plus the album artwork and its hash, taken from the first track that has any
def split_track_artwork(tags, album_artwork, album_artwork_hash, store_individual_artwork):
    track_artwork = None
    if "artwork" in tags and tags["artwork"]:
        track_artwork_data = tags["artwork"][0]["data"]
        track_artwork_hash = hashutil.calculate_string_sha256(track_artwork_data)

        # Set album artwork from first track if not set
        if album_artwork is None:
            album_artwork = tags["artwork"][0]
            album_artwork_hash = track_artwork_hash

        # Only store track artwork if different from album artwork AND storing individual artwork is enabled
        if store_individual_artwork and track_artwork_hash != album_artwork_hash:
            track_artwork = tags["artwork"][0]
    return track_artwork, album_artwork, album_artwork_hash

# A track's tags without artwork, with its track number, album and album artist
# filled in and the forced tags applied over them
def build_track_tags(tags, track_index, default_album, use_index_for_track_number, force_tags):

    # Remove artwork from track tags (will be stored separately)
    track_tags = tags.copy()
    if "artwork" in track_tags:
        del track_tags["artwork"]

    # Handle track numbering
    if use_index_for_track_number:
        track_tags["track_number"] = str(track_index)
    elif "track_number" not in track_tags or not track_tags["track_number"]:
        track_tags["track_number"] = str(track_index)

    # Fill album-level tags so they get written on apply (yt-dlp does not embed these)
    if not track_tags.get("album"):
        track_tags["album"] = default_album
    if not track_tags.get("album_artist"):
        album_artist = track_tags.get("artist", "")
        if album_artist:
            track_tags["album_artist"] = album_artist

    # Force overridden tags (win over anything read from the file)
    if force_tags:
        track_tags.update(force_tags)
    return track_tags

# Album, album artist, artist, year and genre read from a track's tags, with the forced tags applied
def build_album_info(tags, default_album, genre_type, force_tags):
    album_info = {
        "album": tags.get("album") or default_album,
        "album_artist": tags.get("album_artist") or tags.get("artist", ""),
        "artist": tags.get("artist", ""),
        "year": tags.get("year", ""),
        "genre": tags.get("genre", genre_type.value if genre_type else "")
    }

    # Force overridden tags at the album level as well
    if force_tags:
        for field in album_info:
            if field in force_tags:
                album_info[field] = force_tags[field]
    return album_info

# The folder's audio files (MP3 and M4A/M4B), sorted by name; None, after a warning, when there are none
def list_album_audio_files(album_dir):
    audio_files = paths.build_file_list_by_extensions(album_dir, extensions=['.mp3', '.m4a', '.m4b', '.mp4', '.aac'])
    if not audio_files:
        logger.log_warning(f"No audio files found in {album_dir}")
        return None
    audio_files.sort()
    return audio_files

# A track's filename and tags, with its own artwork when it has any
def build_track_info(audio_file, track_tags, track_artwork):
    track_info = {
        "filename": paths.get_filename_file(audio_file),
        "tags": track_tags
    }

    # Add track-specific artwork if different
    if track_artwork:
        track_info["artwork"] = track_artwork
    return track_info

# The album's info, tracks, folder name and track count, with its artwork when found and not empty
def build_album_result(album_dir, album_info, tracks, album_artwork):
    result = {
        "album_info": album_info,
        "tracks": tracks,
        "album_path": paths.get_filename_file(album_dir),
        "total_tracks": len(tracks)
    }

    # Add album artwork if found and not empty
    if album_artwork and album_artwork.get("data"):
        result["album_artwork"] = album_artwork
    return result

# A track's tags to write, with its own artwork or else the album artwork
def build_track_write_tags(track, album_artwork):
    track_tags = track["tags"].copy()
    if "artwork" in track:
        track_tags["artwork"] = [track["artwork"]]
    elif album_artwork:
        track_tags["artwork"] = [album_artwork]
    return track_tags

# Each (track number, file, tags) as track info, the album info from the first of them, and
# the album artwork from the first track that has any
def assemble_album_tracks(
    tagged_tracks,
    default_album,
    genre_type,
    store_individual_artwork = False,
    use_index_for_track_number = False,
    force_tags = None):
    tracks = []
    album_info = {}
    album_artwork = None
    album_artwork_hash = None
    for track_index, audio_file, tags in tagged_tracks:

        # Handle artwork
        track_artwork, album_artwork, album_artwork_hash = split_track_artwork(
            tags,
            album_artwork,
            album_artwork_hash,
            store_individual_artwork)

        # Store track info
        track_tags = build_track_tags(tags, track_index, default_album, use_index_for_track_number, force_tags)
        tracks.append(build_track_info(audio_file, track_tags, track_artwork))

        # Collect album-level info from first track
        if not album_info:
            album_info = build_album_info(tags, default_album, genre_type, force_tags)
    return tracks, album_info, album_artwork

# AudioMetadata's methods for a whole album directory: reading, setting and clearing
# the tags its tracks share
class AlbumTagsMixin:

    # Path, size, bitrate, length, sample rate, channels and tag presence, read as an MP3; None when unreadable
    def get_audio_file_info(self, audio_file, verbose = False, exit_on_failure = False):
        audio = load_audio_file(
            audio_file, self.open_mp3_file, self.mutagen.MutagenError, "Failed to get MP3 file info",
            "Reading MP3 file info from %s" % audio_file, verbose = verbose, exit_on_failure = exit_on_failure)
        if audio is None:
            return None
        return build_audio_file_info(audio_file, audio)

    # The file read as an MP3 with its ID3 tag
    def open_mp3_file(self, audio_file):
        return self.mp3_class(audio_file, ID3 = self.id3_class)

    # Album info, per-track tags and shared artwork for every audio file in the folder, sorted by name; None when there are none
    def get_album_tags(
        self,
        album_dir,
        genre_type,
        store_individual_artwork = False,
        exclude_comments = False,
        use_index_for_track_number = False,
        force_tags = None,
        verbose = False,
        exit_on_failure = False):

        # Check album exists
        if not paths.is_path_directory(album_dir):
            logger.log_error(f"Album directory not found: {album_dir}")
            return None

        # Get all audio files (MP3 and M4A/M4B), sorted by name
        audio_files = list_album_audio_files(album_dir)
        if not audio_files:
            return None

        # Album-level defaults (folder name is the album; artist folder is the album artist)
        default_album = paths.get_filename_file(album_dir)

        # Extract tags from all tracks
        tracks, album_info, album_artwork = self.read_album_tracks(
            audio_files,
            default_album,
            genre_type,
            store_individual_artwork = store_individual_artwork,
            exclude_comments = exclude_comments,
            use_index_for_track_number = use_index_for_track_number,
            force_tags = force_tags,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Build result
        return build_album_result(album_dir, album_info, tracks, album_artwork)

    # Each readable track's info and tags, the album info from the first of them, and
    # the album artwork from the first track that has any
    def read_album_tracks(
        self,
        audio_files,
        default_album,
        genre_type,
        store_individual_artwork = False,
        exclude_comments = False,
        use_index_for_track_number = False,
        force_tags = None,
        verbose = False,
        exit_on_failure = False):
        tagged_tracks = self.read_track_tags(
            audio_files,
            exclude_comments = exclude_comments,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        return assemble_album_tracks(
            tagged_tracks,
            default_album,
            genre_type,
            store_individual_artwork = store_individual_artwork,
            use_index_for_track_number = use_index_for_track_number,
            force_tags = force_tags)

    # (track number by position, file, tags with artwork) for each file whose tags can be read
    def read_track_tags(self, audio_files, exclude_comments = False, verbose = False, exit_on_failure = False):
        tagged_tracks = []
        for track_index, audio_file in enumerate(audio_files, 1):
            tags = self.get_tags(
                audio_file,
                include_artwork = True,
                exclude_comments = exclude_comments,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            if tags is not None:
                tagged_tracks.append((track_index, audio_file, tags))
        return tagged_tracks

    # Write each track's tags and its own or the album artwork back to the files; False at the first missing or failed track
    def set_album_tags(
        self,
        album_dir,
        album_metadata,
        clear_existing = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check album exists
        if not paths.is_path_directory(album_dir):
            logger.log_error(f"Album directory not found: {album_dir}")
            return False

        # Check tracks
        if "tracks" not in album_metadata:
            logger.log_error("No tracks found in album metadata")
            return False

        # Get album artwork if available
        album_artwork = album_metadata.get("album_artwork")

        # Apply tags
        for track in album_metadata["tracks"]:
            audio_file = paths.join_paths(album_dir, track["filename"])
            if not paths.is_path_file(audio_file):
                logger.log_error(f"Track file not found: {audio_file}")
                return False

            # Set tags (auto-detects format)
            if not self.set_tags(
                audio_file,
                build_track_write_tags(track, album_artwork),
                clear_existing = clear_existing,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure):
                return False
        return True

    # Strip tags from every audio file in the folder, optionally keeping artwork; False at the first failure
    def clear_album_tags(
        self,
        album_dir,
        preserve_artwork = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check album exists
        if not paths.is_path_directory(album_dir):
            logger.log_error(f"Album directory not found: {album_dir}")
            return False

        # Get all audio files (MP3 and M4A/M4B)
        audio_files = paths.build_file_list_by_extensions(album_dir, extensions=['.mp3', '.m4a', '.m4b', '.mp4', '.aac'])

        # Remove tags (auto-detects format)
        for audio_file in audio_files:
            if not self.remove_tags(
                audio_file,
                preserve_artwork = preserve_artwork,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure):
                return False
        return True
