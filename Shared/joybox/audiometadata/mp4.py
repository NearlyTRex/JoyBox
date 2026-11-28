# Imports
import base64

# Local imports
from joybox.audiometadata.audiofile import build_audio_file_info, load_audio_file
from joybox import logger
from joybox import paths

# The atom value for a tag: a (number, total) pair for track and disc numbers, an
# int for bpm, a string otherwise; ValueError when a numeric tag is not a number
def build_mp4_tag_value(tag_name, value):
    if tag_name in ["track_number", "disc_number"]:
        if "/" in str(value):
            num, total = str(value).split("/", 1)
            return [(int(num), int(total))]
        return [(int(value), 0)]
    if tag_name == "bpm":
        return [int(value)]
    return [str(value)]

# AudioMetadata's iTunes-style tag methods for MP4 and M4A files, over the mutagen
# class and tag mappings its constructor loads
class Mp4TagsMixin:

    # An MP4/M4A file's text atoms as strings (number pairs as n/total) and its covers as base64 artwork; empty when untagged, None when unreadable
    def get_mp4_tags(
        self,
        audio_file,
        include_artwork = True,
        verbose = False,
        exit_on_failure = False):

        # Read tags from audio file
        audio = self.load_mp4_file(audio_file, f"Reading MP4 tags from {audio_file}", verbose, exit_on_failure)
        if audio is None:
            return None
        if audio.tags is None:
            return {}

        # Extract text tags
        tags = self.read_mp4_text_tags(audio)

        # Extract artwork
        if include_artwork and "covr" in audio.tags:
            artwork = self.read_mp4_artwork(audio)
            if artwork:
                tags["artwork"] = artwork
        return tags

    # The file's mapped text atoms as strings, number pairs as n/total (or n when there is no total)
    def read_mp4_text_tags(self, audio):
        tags = {}
        for mp4_key, tag_name in self.mp4_tag_mappings.items():
            if mp4_key not in audio.tags:
                continue
            value = audio.tags[mp4_key]
            if isinstance(value, list) and len(value) > 0:
                if isinstance(value[0], tuple):
                    num, total = value[0]
                    tags[tag_name] = f"{num}/{total}" if total else str(num)
                else:
                    tags[tag_name] = str(value[0])
        return tags

    # The file's covers as front-cover artwork dicts with base64 data
    def read_mp4_artwork(self, audio):
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
        return artwork

    # Write text, number-pair, bpm and cover atoms from the dict; False when a numeric tag is not a number; skips the save in a pretend run
    def set_mp4_tags(
        self,
        audio_file,
        tags,
        clear_existing = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Load audio file
        audio = self.load_mp4_file(audio_file, f"Setting MP4 tags on {audio_file}", verbose, exit_on_failure)
        if audio is None:
            return False

        # Add tags if they don't exist
        if audio.tags is None:
            audio.add_tags()

        # Clear existing tags if requested
        if clear_existing:
            audio.tags.clear()

        # Set text tags
        if not self.write_mp4_text_tags(audio, tags, audio_file, exit_on_failure):
            return False

        # Set artwork
        if "artwork" in tags:
            covers = self.build_mp4_covers(tags["artwork"])
            if covers:
                audio.tags["covr"] = covers

        # Save changes
        if not pretend_run:
            audio.save()
        return True

    # Store each mapped tag from the dict as its atom; False, after logging the error,
    # at the first numeric tag that is not a number
    def write_mp4_text_tags(self, audio, tags, audio_file, exit_on_failure):
        for tag_name, mp4_key in self.mp4_key_to_tag.items():
            if tag_name not in tags:
                continue
            value = tags[tag_name]
            try:
                audio.tags[mp4_key] = build_mp4_tag_value(tag_name, value)
            except ValueError:
                logger.log_error(f"MP4 {tag_name} must be a number, not '{value}': {audio_file}", quit_program = exit_on_failure)
                return False
        return True

    # MP4 covers from base64 artwork dicts, PNG when the mime says so and JPEG otherwise
    def build_mp4_covers(self, artworks):
        covers = []
        for artwork in artworks:
            image_data = base64.b64decode(artwork["data"])
            mime_type = artwork.get("mime", "image/jpeg")
            if "png" in mime_type.lower():
                img_format = self.mutagen_mp4.MP4Cover.FORMAT_PNG
            else:
                img_format = self.mutagen_mp4.MP4Cover.FORMAT_JPEG
            covers.append(self.mutagen_mp4.MP4Cover(image_data, imageformat = img_format))
        return covers

    # Delete every atom from the file, optionally putting its covers back; True when there was nothing to remove
    def remove_mp4_tags(
        self,
        audio_file,
        preserve_artwork = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Load audio file
        audio = self.load_mp4_file(audio_file, f"Removing MP4 tags from {audio_file}", verbose, exit_on_failure)
        if audio is None:
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

    # The MP4 file opened, logging the action when verbose; None, after logging the
    # error, when the file is missing or unreadable
    def load_mp4_file(self, audio_file, action_message, verbose, exit_on_failure):
        return load_audio_file(
            audio_file, self.mp4_class, self.mutagen.MutagenError, "Failed to load MP4 file",
            action_message, verbose = verbose, exit_on_failure = exit_on_failure)

    # Whether the file has at least one MP4 tag atom; False when missing or unreadable
    def has_mp4_tags(self, audio_file):

        # Check file exists
        if not paths.is_path_file(audio_file):
            return False

        # Load and check tags
        try:
            audio = self.mp4_class(audio_file)
            return audio.tags is not None and len(audio.tags) > 0
        except self.mutagen.MutagenError:
            return False

    # Path, size, bitrate, length, sample rate, channels, tag presence and codec; None when unreadable
    def get_mp4_file_info(self, audio_file, verbose = False, exit_on_failure = False):
        audio = load_audio_file(
            audio_file, self.mp4_class, self.mutagen.MutagenError, "Failed to get MP4 file info",
            "Reading MP4 file info from %s" % audio_file, verbose = verbose, exit_on_failure = exit_on_failure)
        if audio is None:
            return None
        file_info = build_audio_file_info(audio_file, audio)
        file_info["codec"] = getattr(audio.info, "codec", None)
        return file_info
