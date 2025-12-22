# Imports
import os
import sys
import base64
import re
import tempfile

# Local imports
import config
import command
import programs
import system
import logger
import environment
import hashing
import image
import modules

# Audio metadata class
class AudioMetadata:

    # Constructor
    def __init__(self):

        # Import mutagen modules
        self.mutagen = modules.import_python_module_package(
            module_path = programs.GetToolPathConfigValue("Mutagen", "package_dir"),
            module_name = programs.GetToolConfigValue("Mutagen", "package_name"))
        self.mutagen_mp3 = modules.import_python_module_package(
            module_path = programs.GetToolPathConfigValue("MutagenMP3", "package_dir"),
            module_name = programs.GetToolConfigValue("MutagenMP3", "package_name"))
        self.mutagen_id3 = modules.import_python_module_package(
            module_path = programs.GetToolPathConfigValue("MutagenID3", "package_dir"),
            module_name = programs.GetToolConfigValue("MutagenID3", "package_name"))
        self.mutagen_mp4 = modules.import_python_module_package(
            module_path = programs.GetToolPathConfigValue("MutagenMP4", "package_dir"),
            module_name = programs.GetToolConfigValue("MutagenMP4", "package_name"))
        if self.mutagen is None or self.mutagen_mp3 is None or self.mutagen_id3 is None or self.mutagen_mp4 is None:
            raise ImportError("Failed to import mutagen modules")

        # Store MP3 and ID3 classes
        self.mp3_class = self.mutagen_mp3.MP3
        self.id3_class = self.mutagen_id3.ID3

        # Store MP4 class
        self.mp4_class = self.mutagen_mp4.MP4

        # Store frame classes by code
        self.id3_frame_classes = {
            "APIC": self.mutagen_id3.APIC,
            "TIT2": self.mutagen_id3.TIT2,
            "TPE1": self.mutagen_id3.TPE1,
            "TALB": self.mutagen_id3.TALB,
            "TDRC": self.mutagen_id3.TDRC,
            "TCON": self.mutagen_id3.TCON,
            "TPE2": self.mutagen_id3.TPE2,
            "TRCK": self.mutagen_id3.TRCK,
            "TPOS": self.mutagen_id3.TPOS,
            "TBPM": self.mutagen_id3.TBPM,
            "TKEY": self.mutagen_id3.TKEY,
            "TPE3": self.mutagen_id3.TPE3,
            "COMM": self.mutagen_id3.COMM
        }

        # Store frame classes by key
        self.id3_frame_classes_by_key = {
            "title": self.id3_frame_classes["TIT2"],
            "artist": self.id3_frame_classes["TPE1"],
            "album": self.id3_frame_classes["TALB"],
            "year": self.id3_frame_classes["TDRC"],
            "genre": self.id3_frame_classes["TCON"],
            "album_artist": self.id3_frame_classes["TPE2"],
            "track_number": self.id3_frame_classes["TRCK"],
            "disc_number": self.id3_frame_classes["TPOS"],
            "bpm": self.id3_frame_classes["TBPM"],
            "key": self.id3_frame_classes["TKEY"],
            "conductor": self.id3_frame_classes["TPE3"]
        }

        # Store common frame classes
        self.comment_class = self.id3_frame_classes["COMM"]
        self.artwork_class = self.id3_frame_classes["APIC"]

        # Text frame mappings for ID3 (MP3)
        self.text_mappings = {
            "TIT2": "title",
            "TPE1": "artist",
            "TALB": "album",
            "TDRC": "year",
            "TCON": "genre",
            "TPE2": "album_artist",
            "TRCK": "track_number",
            "TPOS": "disc_number",
            "TBPM": "bpm",
            "TKEY": "key",
            "TPE3": "conductor"
        }

        # MP4 tag mappings (iTunes-style tags)
        self.mp4_tag_mappings = {
            "\xa9nam": "title",
            "\xa9ART": "artist",
            "\xa9alb": "album",
            "\xa9day": "year",
            "\xa9gen": "genre",
            "aART": "album_artist",
            "trkn": "track_number",
            "disk": "disc_number",
            "tmpo": "bpm",
            "\xa9wrt": "composer",
            "\xa9cmt": "comment",
            "\xa9too": "encoder",
            "cprt": "copyright",
            "desc": "description",
            "\xa9lyr": "lyrics",
            "purd": "purchase_date",
            "soar": "sort_artist",
            "soal": "sort_album",
            "sonm": "sort_title"
        }

        # Reverse mapping for setting MP4 tags
        self.mp4_key_to_tag = {v: k for k, v in self.mp4_tag_mappings.items()}

    def get_id3_tags(
        self,
        audio_file,
        include_artwork = True,
        exclude_comments = False,
        artwork_format = None,
        verbose = False,
        exit_on_failure = False):

        # Default artwork format to JPEG
        if artwork_format is None:
            artwork_format = config.ImageFileType.JPEG

        # Check file exists
        if not system.IsPathFile(audio_file):
            logger.log_error(f"Audio file not found: {audio_file}")
            return None

        # Read tags from audio file
        logger.log_info(f"Reading ID3 tags from {audio_file}")
        audio = self.mp3_class(audio_file, ID3 = self.id3_class)
        if audio.tags is None:
            logger.log_error(f"Failed to load audio file")
            return {}

        # Extract text frames
        tags = {}
        for frame_id, tag_name in self.text_mappings.items():
            if frame_id in audio.tags:
                tags[tag_name] = str(audio.tags[frame_id])

        # Extract comments
        if not exclude_comments:
            comments = []
            for frame in audio.tags.values():
                if isinstance(frame, self.comment_class):
                    comment_data = {
                        "desc": frame.desc,
                        "lang": frame.lang,
                        "text": str(frame)
                    }
                    comments.append(comment_data)
            if comments:
                tags["comments"] = comments

        # Extract artwork
        if include_artwork:
            artwork = []
            for frame in audio.tags.values():
                if isinstance(frame, self.artwork_class):
                    image_data = frame.data
                    mime_type = frame.mime

                    # Check if image needs conversion
                    target_mime = f"image/{artwork_format.val().lower()}"
                    if mime_type != target_mime:
                        converted_b64_data = image.ConvertImageDataToFormat(
                            image_data = image_data,
                            target_format = artwork_format)
                        if converted_b64_data:
                            artwork_data = {
                                "type": frame.type,
                                "desc": frame.desc,
                                "mime": target_mime,
                                "data": converted_b64_data
                            }
                        else:
                            artwork_data = {
                                "type": frame.type,
                                "desc": frame.desc,
                                "mime": mime_type,
                                "data": base64.b64encode(image_data).decode("utf-8")
                            }
                    else:
                        artwork_data = {
                            "type": frame.type,
                            "desc": frame.desc,
                            "mime": mime_type,
                            "data": base64.b64encode(image_data).decode("utf-8")
                        }
                    artwork.append(artwork_data)
            if artwork:
                tags["artwork"] = artwork
        return tags

    def set_id3_tags(
        self,
        audio_file,
        tags,
        clear_existing = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check file exists
        if not system.IsPathFile(audio_file):
            logger.log_error(f"Audio file not found: {audio_file}")
            return False

        # Load audio file
        logger.log_info(f"Setting ID3 tags on {audio_file}")
        audio = self.mp3_class(audio_file, ID3 = self.id3_class)

        # Add ID3 tags if they don"t exist
        if audio.tags is None:
            audio.add_tags()

        # Clear existing tags if requested
        if clear_existing:
            audio.tags.clear()

        # Set text frames
        for tag_name, frame_class in self.id3_frame_classes_by_key.items():
            if tag_name in tags:
                audio.tags[frame_class.__name__] = frame_class(encoding = 3, text = str(tags[tag_name]))

        # Set comments
        if "comments" in tags:
            for comment in tags["comments"]:
                audio.tags[f"COMM:{comment.get('desc', '')}"] = self.comment_class(
                    encoding = 3,
                    lang = comment.get("lang", "eng"),
                    desc = comment.get("desc", ""),
                    text = comment.get("text", ""))

        # Set artwork
        if "artwork" in tags:
            for artwork in tags["artwork"]:
                image_data = base64.b64decode(artwork["data"])
                audio.tags[f"APIC:{artwork['desc']}"] = self.artwork_class(
                    encoding = 3,
                    mime = artwork["mime"],
                    type = artwork["type"],
                    desc = artwork["desc"],
                    data = image_data)

        # Save changes
        audio.save()
        return True

    def remove_id3_tags(
        self,
        audio_file,
        preserve_artwork = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check file exists
        if not system.IsPathFile(audio_file):
            logger.log_error(f"Audio file not found: {audio_file}")
            return False

        # Load audio file
        logger.log_info(f"Removing ID3 tags from {audio_file}")
        audio = self.mp3_class(audio_file, ID3 = self.id3_class)

        # No tags to remove
        if audio.tags is None:
            return True

        # Preserve artwork if requested
        preserved_artwork = []
        if preserve_artwork:
            for frame in audio.tags.values():
                if isinstance(frame, self.artwork_class):
                    preserved_artwork.append(frame)

        # Delete all tags
        audio.delete()

        # Restore artwork if preserved
        if preserve_artwork and preserved_artwork:
            audio.add_tags()
            for artwork in preserved_artwork:
                audio.tags[f"APIC:{artwork.desc}"] = artwork

        # Save changes
        audio.save()
        return True

    def has_id3_tags(self, audio_file):

        # Check file exists
        if not system.IsPathFile(audio_file):
            return False

        # Load and check tags
        audio = self.mp3_class(audio_file, ID3 = self.id3_class)
        return audio.tags is not None and len(audio.tags) > 0

    ###########################################################
    # MP4/M4A Tag Methods
    ###########################################################

    def get_mp4_tags(
        self,
        audio_file,
        include_artwork = True,
        verbose = False,
        exit_on_failure = False):

        # Check file exists
        if not system.IsPathFile(audio_file):
            logger.log_error(f"Audio file not found: {audio_file}")
            return None

        # Read tags from audio file
        logger.log_info(f"Reading MP4 tags from {audio_file}")
        try:
            audio = self.mp4_class(audio_file)
        except Exception as e:
            logger.log_error(f"Failed to load MP4 file: {e}")
            return None
        if audio.tags is None:
            return {}

        # Extract text tags
        tags = {}
        for mp4_key, tag_name in self.mp4_tag_mappings.items():
            if mp4_key in audio.tags:
                value = audio.tags[mp4_key]
                if isinstance(value, list) and len(value) > 0:
                    if isinstance(value[0], tuple):
                        num, total = value[0]
                        tags[tag_name] = f"{num}/{total}" if total else str(num)
                    else:
                        tags[tag_name] = str(value[0])

        # Extract artwork
        if include_artwork and "covr" in audio.tags:
            artwork = []
            for cover in audio.tags["covr"]:
                if hasattr(cover, "imageformat"):
                    if cover.imageformat == self.mutagen_mp4.MP4Cover.FORMAT_JPEG:
                        mime_type = "image/jpeg"
                    elif cover.imageformat == self.mutagen_mp4.MP4Cover.FORMAT_PNG:
                        mime_type = "image/png"
                    else:
                        mime_type = "image/jpeg"
                else:
                    mime_type = "image/jpeg"
                artwork_data = {
                    "type": 3,  # Front cover
                    "desc": "",
                    "mime": mime_type,
                    "data": base64.b64encode(bytes(cover)).decode("utf-8")
                }
                artwork.append(artwork_data)
            if artwork:
                tags["artwork"] = artwork
        return tags

    def set_mp4_tags(
        self,
        audio_file,
        tags,
        clear_existing = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check file exists
        if not system.IsPathFile(audio_file):
            logger.log_error(f"Audio file not found: {audio_file}")
            return False

        # Load audio file
        logger.log_info(f"Setting MP4 tags on {audio_file}")
        try:
            audio = self.mp4_class(audio_file)
        except Exception as e:
            logger.log_error(f"Failed to load MP4 file: {e}")
            return False

        # Add tags if they don't exist
        if audio.tags is None:
            audio.add_tags()

        # Clear existing tags if requested
        if clear_existing:
            audio.tags.clear()

        # Set text tags
        for tag_name, mp4_key in self.mp4_key_to_tag.items():
            if tag_name in tags:
                value = tags[tag_name]
                if tag_name in ["track_number", "disc_number"]:
                    if "/" in str(value):
                        num, total = str(value).split("/", 1)
                        audio.tags[mp4_key] = [(int(num), int(total))]
                    else:
                        audio.tags[mp4_key] = [(int(value), 0)]
                elif tag_name == "bpm":
                    audio.tags[mp4_key] = [int(value)]
                else:
                    audio.tags[mp4_key] = [str(value)]

        # Set artwork
        if "artwork" in tags:
            covers = []
            for artwork in tags["artwork"]:
                image_data = base64.b64decode(artwork["data"])
                mime_type = artwork.get("mime", "image/jpeg")
                if "png" in mime_type.lower():
                    img_format = self.mutagen_mp4.MP4Cover.FORMAT_PNG
                else:
                    img_format = self.mutagen_mp4.MP4Cover.FORMAT_JPEG
                covers.append(self.mutagen_mp4.MP4Cover(image_data, imageformat = img_format))
            if covers:
                audio.tags["covr"] = covers

        # Save changes
        if not pretend_run:
            audio.save()
        return True

    def remove_mp4_tags(
        self,
        audio_file,
        preserve_artwork = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check file exists
        if not system.IsPathFile(audio_file):
            logger.log_error(f"Audio file not found: {audio_file}")
            return False

        # Load audio file
        logger.log_info(f"Removing MP4 tags from {audio_file}")
        try:
            audio = self.mp4_class(audio_file)
        except Exception as e:
            logger.log_error(f"Failed to load MP4 file: {e}")
            return False

        # No tags to remove
        if audio.tags is None:
            return True

        # Preserve artwork if requested
        preserved_covers = None
        if preserve_artwork and "covr" in audio.tags:
            preserved_covers = audio.tags["covr"]

        # Delete all tags
        audio.delete()

        # Restore artwork if preserved
        if preserve_artwork and preserved_covers:
            audio.add_tags()
            audio.tags["covr"] = preserved_covers

        # Save changes
        if not pretend_run:
            audio.save()
        return True

    def has_mp4_tags(self, audio_file):

        # Check file exists
        if not system.IsPathFile(audio_file):
            return False

        # Load and check tags
        try:
            audio = self.mp4_class(audio_file)
            return audio.tags is not None and len(audio.tags) > 0
        except:
            return False

    def get_mp4_file_info(self, audio_file, verbose = False, exit_on_failure = False):

        # Check file exists
        if not system.IsPathFile(audio_file):
            logger.log_error(f"Audio file not found: {audio_file}")
            return None

        # Get audio info
        try:
            audio = self.mp4_class(audio_file)
            file_info = {
                "path": audio_file,
                "size": os.path.getsize(audio_file),
                "bitrate": getattr(audio.info, "bitrate", 0),
                "length": getattr(audio.info, "length", 0),
                "sample_rate": getattr(audio.info, "sample_rate", 0),
                "channels": getattr(audio.info, "channels", 0),
                "has_tags": audio.tags is not None,
                "codec": getattr(audio.info, "codec", None)
            }
            return file_info
        except Exception as e:
            logger.log_error(f"Failed to get MP4 file info: {e}")
            return None

    ###########################################################
    # Generic Methods (auto-detect format)
    ###########################################################

    def get_tags(
        self,
        audio_file,
        include_artwork = True,
        exclude_comments = False,
        verbose = False,
        exit_on_failure = False):

        # Check file exists
        if not system.IsPathFile(audio_file):
            logger.log_error(f"Audio file not found: {audio_file}")
            return None

        # Detect format by extension
        ext = system.GetFilenameExtension(audio_file).lower()
        if ext in [".m4a", ".m4b", ".mp4", ".aac"]:
            return self.get_mp4_tags(
                audio_file = audio_file,
                include_artwork = include_artwork,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
        else:
            return self.get_id3_tags(
                audio_file = audio_file,
                include_artwork = include_artwork,
                exclude_comments = exclude_comments,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

    def set_tags(
        self,
        audio_file,
        tags,
        clear_existing = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check file exists
        if not system.IsPathFile(audio_file):
            logger.log_error(f"Audio file not found: {audio_file}")
            return False

        # Detect format by extension
        ext = system.GetFilenameExtension(audio_file).lower()
        if ext in [".m4a", ".m4b", ".mp4", ".aac"]:
            return self.set_mp4_tags(
                audio_file = audio_file,
                tags = tags,
                clear_existing = clear_existing,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        else:
            return self.set_id3_tags(
                audio_file = audio_file,
                tags = tags,
                clear_existing = clear_existing,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

    def remove_tags(
        self,
        audio_file,
        preserve_artwork = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Check file exists
        if not system.IsPathFile(audio_file):
            logger.log_error(f"Audio file not found: {audio_file}")
            return False

        # Detect format by extension
        ext = system.GetFilenameExtension(audio_file).lower()
        if ext in [".m4a", ".m4b", ".mp4", ".aac"]:
            return self.remove_mp4_tags(
                audio_file = audio_file,
                preserve_artwork = preserve_artwork,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        else:
            return self.remove_id3_tags(
                audio_file = audio_file,
                preserve_artwork = preserve_artwork,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)

    def has_tags(self, audio_file):

        # Check file exists
        if not system.IsPathFile(audio_file):
            return False

        # Detect format by extension
        ext = system.GetFilenameExtension(audio_file).lower()
        if ext in [".m4a", ".m4b", ".mp4", ".aac"]:
            return self.has_mp4_tags(audio_file)
        else:
            return self.has_id3_tags(audio_file)

    def get_file_info(self, audio_file, verbose = False, exit_on_failure = False):

        # Check file exists
        if not system.IsPathFile(audio_file):
            logger.log_error(f"Audio file not found: {audio_file}")
            return None

        # Detect format by extension
        ext = system.GetFilenameExtension(audio_file).lower()
        if ext in [".m4a", ".m4b", ".mp4", ".aac"]:
            return self.get_mp4_file_info(
                audio_file = audio_file,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
        else:
            return self.get_audio_file_info(
                audio_file = audio_file,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

    ###########################################################
    # Album-level Methods
    ###########################################################

    def get_audio_file_info(self, audio_file, verbose = False, exit_on_failure = False):

        # Check file exists
        if not system.IsPathFile(audio_file):
            logger.log_error(f"Audio file not found: {audio_file}")
            return None

        # Get audio info
        audio = self.mp3_class(audio_file, ID3 = self.id3_class)
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
        verbose = False,
        exit_on_failure = False):

        # Check album exists
        if not system.IsPathDirectory(album_dir):
            logger.log_error(f"Album directory not found: {album_dir}")
            return None

        # Get all audio files (MP3 and M4A/M4B)
        audio_files = system.BuildFileListByExtensions(album_dir, extensions=['.mp3', '.m4a', '.m4b', '.mp4', '.aac'])
        if not audio_files:
            logger.log_warning(f"No audio files found in {album_dir}")
            return None

        # Sort files by name
        audio_files.sort()

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
                    track_artwork_hash = hashing.CalculateStringSHA256(track_artwork_data)

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

                # Store track info
                track_info = {
                    "filename": system.GetFilenameFile(audio_file),
                    "tags": track_tags
                }

                # Add track-specific artwork if different
                if track_artwork:
                    track_info["artwork"] = track_artwork
                tracks.append(track_info)

                # Collect album-level info from first track
                if not album_info:
                    album_info = {
                        "album": tags.get("album", system.GetFilenameFile(album_dir)),
                        "album_artist": tags.get("album_artist", tags.get("artist", "")),
                        "artist": tags.get("artist", ""),
                        "year": tags.get("year", ""),
                        "genre": tags.get("genre", genre_type.value if genre_type else "")
                    }

        # Build result
        result = {
            "album_info": album_info,
            "tracks": tracks,
            "album_path": system.GetFilenameFile(album_dir),
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
        if not system.IsPathDirectory(album_dir):
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
            audio_file = system.JoinPaths(album_dir, track["filename"])
            if system.IsPathFile(audio_file):

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
        if not system.IsPathDirectory(album_dir):
            logger.log_error(f"Album directory not found: {album_dir}")
            return False

        # Get all audio files (MP3 and M4A/M4B)
        audio_files = system.BuildFileListByExtensions(album_dir, extensions=['.mp3', '.m4a', '.m4b', '.mp4', '.aac'])

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
