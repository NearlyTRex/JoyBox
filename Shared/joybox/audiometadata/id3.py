# Imports
import base64

# Local imports
from joybox import config
from joybox import logger
from joybox import image
from joybox import paths

# AudioMetadata's ID3 tag methods for MP3 files and raw ADTS .aac streams, over
# the mutagen classes and frame mappings its constructor loads
class Id3TagsMixin:

    # An MP3's text frames, comments and artwork as a dict, artwork base64 and converted to the format (JPEG by default); empty when untagged, None when unreadable
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

        # Read tags from audio file
        audio = self.load_id3_file(audio_file, f"Reading ID3 tags from {audio_file}", verbose, exit_on_failure)
        if audio is None:
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
            comments = self.read_id3_comments(audio)
            if comments:
                tags["comments"] = comments

        # Extract artwork
        if include_artwork:
            artwork = self.read_id3_artwork(audio, artwork_format)
            if artwork:
                tags["artwork"] = artwork
        return tags

    # The MP3's comment frames as desc, lang and text dicts
    def read_id3_comments(self, audio):
        comments = []
        for frame in audio.tags.values():
            if isinstance(frame, self.comment_class):
                comment_data = {
                    "desc": frame.desc,
                    "lang": frame.lang,
                    "text": str(frame)
                }
                comments.append(comment_data)
        return comments

    # The MP3's picture frames as type, desc, mime and base64 data dicts
    def read_id3_artwork(self, audio, artwork_format):
        artwork = []
        for frame in audio.tags.values():
            if isinstance(frame, self.artwork_class):
                artwork.append(self.read_id3_artwork_frame(frame, artwork_format))
        return artwork

    # One picture frame as a dict, converted to the format; the original image when it
    # already is that format or the conversion fails
    def read_id3_artwork_frame(self, frame, artwork_format):
        image_data = frame.data
        mime_type = frame.mime

        # Check if image needs conversion
        target_mime = f"image/{artwork_format.val().lower()}"
        if mime_type != target_mime:
            converted_b64_data = image.convert_image_data_to_format(
                image_data = image_data,
                target_format = artwork_format)
            if converted_b64_data:
                return {
                    "type": frame.type,
                    "desc": frame.desc,
                    "mime": target_mime,
                    "data": converted_b64_data
                }
        return {
            "type": frame.type,
            "desc": frame.desc,
            "mime": mime_type,
            "data": base64.b64encode(image_data).decode("utf-8")
        }

    # Write text frames, comments and base64 artwork from the dict into the MP3, optionally clearing it first; skips the save in a pretend run
    def set_id3_tags(
        self,
        audio_file,
        tags,
        clear_existing = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Load audio file
        audio = self.load_id3_file(audio_file, f"Setting ID3 tags on {audio_file}", verbose, exit_on_failure)
        if audio is None:
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
            self.write_id3_comments(audio, tags["comments"])

        # Set artwork
        if "artwork" in tags:
            self.write_id3_artwork(audio, tags["artwork"])

        # Save changes
        if not pretend_run:
            audio.save()
        return True

    # Store each comment dict as a COMM frame keyed by its desc
    def write_id3_comments(self, audio, comments):
        for comment in comments:
            audio.tags[f"COMM:{comment.get('desc', '')}"] = self.comment_class(
                encoding = 3,
                lang = comment.get("lang", "eng"),
                desc = comment.get("desc", ""),
                text = comment.get("text", ""))

    # Store each base64 artwork dict as an APIC frame keyed by its desc
    def write_id3_artwork(self, audio, artworks):
        for artwork in artworks:
            image_data = base64.b64decode(artwork["data"])
            audio.tags[f"APIC:{artwork['desc']}"] = self.artwork_class(
                encoding = 3,
                mime = artwork["mime"],
                type = artwork["type"],
                desc = artwork["desc"],
                data = image_data)

    # Delete the MP3's ID3 tag, optionally putting its artwork frames back; True when there was nothing to remove
    def remove_id3_tags(
        self,
        audio_file,
        preserve_artwork = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Load audio file
        audio = self.load_id3_file(audio_file, f"Removing ID3 tags from {audio_file}", verbose, exit_on_failure)
        if audio is None:
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

    # The file opened for its ID3 tag, logging the action when verbose; None, after
    # logging the error, when the file is missing or unreadable
    def load_id3_file(self, audio_file, action_message, verbose, exit_on_failure):

        # Check file exists
        if not paths.is_path_file(audio_file):
            logger.log_error(f"Audio file not found: {audio_file}", quit_program = exit_on_failure)
            return None

        # Load audio file
        if verbose:
            logger.log_info(action_message)
        try:
            return self.open_id3_file(audio_file)
        except self.mutagen.MutagenError as e:
            logger.log_error(f"Failed to load MP3 file: {e}", quit_program = exit_on_failure)
            return None

    # The file's audio and ID3 tag: an ADTS stream's standalone tag for a raw .aac, else the MP3 reader
    def open_id3_file(self, audio_file):
        if self.is_adts_audio_file(audio_file):
            return self.open_adts_id3_file(audio_file)
        return self.mp3_class(audio_file, ID3 = self.id3_class)

    # Whether the MP3 has an ID3 tag with at least one frame; False when missing or unreadable
    def has_id3_tags(self, audio_file):

        # Check file exists
        if not paths.is_path_file(audio_file):
            return False

        # Load and check tags
        try:
            audio = self.open_id3_file(audio_file)
            return audio.tags is not None and len(audio.tags) > 0
        except self.mutagen.MutagenError:
            return False
