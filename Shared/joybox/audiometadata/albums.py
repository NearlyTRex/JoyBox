# Imports
import os

# Local imports
from joybox import logger
from joybox import hashutil
from joybox import paths

# AudioMetadata's methods for a whole album directory: reading, setting and clearing
# the tags its tracks share
class AlbumTagsMixin:

    def get_audio_file_info(self, audio_file, verbose = False, exit_on_failure = False):

        # Check file exists
        if not paths.is_path_file(audio_file):
            logger.log_error(f"Audio file not found: {audio_file}", quit_program = exit_on_failure)
            return None

        # Log what is read
        if verbose:
            logger.log_info(f"Reading MP3 file info from {audio_file}")

        # Get audio info
        try:
            audio = self.mp3_class(audio_file, ID3 = self.id3_class)
        except Exception as e:
            logger.log_error(f"Failed to get MP3 file info: {e}", quit_program = exit_on_failure)
            return None
        file_info = {
            "path": audio_file,
            "size": os.path.getsize(audio_file),
            "bitrate": getattr(audio.info, "bitrate", 0),
            "length": getattr(audio.info, "length", 0),
            "sample_rate": getattr(audio.info, "sample_rate", 0),
            "channels": getattr(audio.info, "channels", 0),
            "has_tags": audio.tags is not None
        }
        return file_info

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

        # Get all audio files (MP3 and M4A/M4B)
        audio_files = paths.build_file_list_by_extensions(album_dir, extensions=['.mp3', '.m4a', '.m4b', '.mp4', '.aac'])
        if not audio_files:
            logger.log_warning(f"No audio files found in {album_dir}")
            return None

        # Sort files by name
        audio_files.sort()

        # Album-level defaults (folder name is the album; artist folder is the album artist)
        default_album = paths.get_filename_file(album_dir)

        # Extract tags from all tracks
        tracks = []
        album_info = {}
        album_artwork = None
        album_artwork_hash = None
        for track_index, audio_file in enumerate(audio_files, 1):
            tags = self.get_tags(
                audio_file,
                include_artwork = True,
                exclude_comments = exclude_comments,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            if tags is not None:

                # Handle artwork
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

                # Store track info
                track_info = {
                    "filename": paths.get_filename_file(audio_file),
                    "tags": track_tags
                }

                # Add track-specific artwork if different
                if track_artwork:
                    track_info["artwork"] = track_artwork
                tracks.append(track_info)

                # Collect album-level info from first track
                if not album_info:
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

        # Build result
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
            if paths.is_path_file(audio_file):

                # Prepare tags for this track
                track_tags = track["tags"].copy()

                # Add artwork (track-specific or album artwork)
                if "artwork" in track:
                    track_tags["artwork"] = [track["artwork"]]
                elif album_artwork:
                    track_tags["artwork"] = [album_artwork]

                # Set tags (auto-detects format)
                if not self.set_tags(
                    audio_file,
                    track_tags,
                    clear_existing = clear_existing,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure):
                    return False
            else:
                logger.log_error(f"Track file not found: {audio_file}")
                return False
        return True

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
