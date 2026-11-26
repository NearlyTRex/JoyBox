# Imports
import base64

# Local imports
from joybox import config
from joybox import logger
from joybox import image
from joybox import paths

# AudioMetadata's ID3 tag methods for MP3 files, over the mutagen classes and
# frame mappings its constructor loads
class Id3TagsMixin:

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
        if not paths.is_path_file(audio_file):
            logger.log_error(f"Audio file not found: {audio_file}", quit_program = exit_on_failure)
            return None

        # Read tags from audio file
        if verbose:
            logger.log_info(f"Reading ID3 tags from {audio_file}")
        try:
            audio = self.mp3_class(audio_file, ID3 = self.id3_class)
        except Exception as e:
            logger.log_error(f"Failed to load MP3 file: {e}", quit_program = exit_on_failure)
            return None
        if audio.tags is None:
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
                        converted_b64_data = image.convert_image_data_to_format(
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
        if not paths.is_path_file(audio_file):
            logger.log_error(f"Audio file not found: {audio_file}", quit_program = exit_on_failure)
            return False

        # Load audio file
        if verbose:
            logger.log_info(f"Setting ID3 tags on {audio_file}")
        try:
            audio = self.mp3_class(audio_file, ID3 = self.id3_class)
        except Exception as e:
            logger.log_error(f"Failed to load MP3 file: {e}", quit_program = exit_on_failure)
            return False

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
        if not pretend_run:
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
        if not paths.is_path_file(audio_file):
            logger.log_error(f"Audio file not found: {audio_file}", quit_program = exit_on_failure)
            return False

        # Load audio file
        if verbose:
            logger.log_info(f"Removing ID3 tags from {audio_file}")
        try:
            audio = self.mp3_class(audio_file, ID3 = self.id3_class)
        except Exception as e:
            logger.log_error(f"Failed to load MP3 file: {e}", quit_program = exit_on_failure)
            return False

        # No tags to remove
        if audio.tags is None or pretend_run:
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
            if audio.tags is None:
                audio.add_tags()
            for artwork in preserved_artwork:
                audio.tags[f"APIC:{artwork.desc}"] = artwork

        # Save changes
        audio.save()
        return True

    def has_id3_tags(self, audio_file):

        # Check file exists
        if not paths.is_path_file(audio_file):
            return False

        # Load and check tags
        try:
            audio = self.mp3_class(audio_file, ID3 = self.id3_class)
            return audio.tags is not None and len(audio.tags) > 0
        except Exception:
            return False
