# Imports
import os
import base64

# Local imports
from joybox import logger
from joybox import paths

# AudioMetadata's iTunes-style tag methods for MP4 and M4A files, over the mutagen
# class and tag mappings its constructor loads
class Mp4TagsMixin:

    def get_mp4_tags(
        self,
        audio_file,
        include_artwork = True,
        verbose = False,
        exit_on_failure = False):

        # Check file exists
        if not paths.is_path_file(audio_file):
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
                mime_type = "image/jpeg"
                if cover.imageformat == self.mutagen_mp4.MP4Cover.FORMAT_PNG:
                    mime_type = "image/png"
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
        if not paths.is_path_file(audio_file):
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
                try:
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
                except ValueError:
                    logger.log_error(f"MP4 {tag_name} must be a number, not '{value}': {audio_file}")
                    return False

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
        if not paths.is_path_file(audio_file):
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
        if audio.tags is None or pretend_run:
            return True

        # Preserve artwork if requested
        preserved_covers = None
        if preserve_artwork and "covr" in audio.tags:
            preserved_covers = audio.tags["covr"]

        # Delete all tags
        audio.delete()

        # Restore artwork if preserved
        if preserve_artwork and preserved_covers:
            if audio.tags is None:
                audio.add_tags()
            audio.tags["covr"] = preserved_covers

        # Save changes
        audio.save()
        return True

    def has_mp4_tags(self, audio_file):

        # Check file exists
        if not paths.is_path_file(audio_file):
            return False

        # Load and check tags
        try:
            audio = self.mp4_class(audio_file)
            return audio.tags is not None and len(audio.tags) > 0
        except Exception:
            return False

    def get_mp4_file_info(self, audio_file, verbose = False, exit_on_failure = False):

        # Check file exists
        if not paths.is_path_file(audio_file):
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
