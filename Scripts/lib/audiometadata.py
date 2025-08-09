# Imports
import os
import sys
import base64
import re

# Local imports
import config
import command
import programs
import system
import environment

# Audio metadata class
class AudioMetadata:

    # Constructor
    def __init__(self):

        # Import main mutagen module
        self.mutagen = environment.ImportPythonModuleFile(
            module_path = programs.GetToolProgram("Mutagen"),
            module_name = "mutagen")
        if self.mutagen is None:
            raise ImportError("Failed to import mutagen module")

        # Store MP3 and ID3 classes
        self.mp3_class = self.mutagen.mp3.MP3
        self.id3_class = self.mutagen.id3.ID3

        # Store frame classes by code
        self.id3_frame_classes = {
            "APIC": self.mutagen.id3.APIC,
            "TIT2": self.mutagen.id3.TIT2,
            "TPE1": self.mutagen.id3.TPE1,
            "TALB": self.mutagen.id3.TALB,
            "TDRC": self.mutagen.id3.TDRC,
            "TCON": self.mutagen.id3.TCON,
            "TPE2": self.mutagen.id3.TPE2,
            "TRCK": self.mutagen.id3.TRCK,
            "TPOS": self.mutagen.id3.TPOS,
            "TBPM": self.mutagen.id3.TBPM,
            "TKEY": self.mutagen.id3.TKEY,
            "TPE3": self.mutagen.id3.TPE3,
            "COMM": self.mutagen.id3.COMM
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

        # Text frame mappings
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

    def get_id3_tags(
        self,
        audio_file,
        include_artwork = True,
        verbose = False,
        exit_on_failure = False):

        # Check file exists
        if not system.IsPathFile(audio_file):
            system.LogError(f"Audio file not found: {audio_file}")
            return None

        # Read tags from audio file
        system.LogInfo(f"Reading ID3 tags from {audio_file}")
        audio = self.mp3_class(audio_file, ID3 = self.id3_class)
        if audio.tags is None:
            system.LogError(f"Failed to load audio file")
            return None

        # Extract text frames
        tags = {}
        for frame_id, tag_name in text_mappings.items():
            if frame_id in audio.tags:
                tags[tag_name] = str(audio.tags[frame_id])

        # Extract comments
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
                    artwork_data = {
                        "type": frame.type,
                        "desc": frame.desc,
                        "mime": frame.mime,
                        "data": base64.b64encode(frame.data).decode("utf-8")
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
            system.LogError(f"Audio file not found: {audio_file}")
            return False

        # Load audio file
        system.LogInfo(f"Setting ID3 tags on {audio_file}")
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
                audio.tags[f"COMM:{comment.get("desc", "")}"] = self.comment_class(
                    encoding = 3,
                    lang = comment.get("lang", "eng"),
                    desc = comment.get("desc", ""),
                    text = comment.get("text", ""))

        # Set artwork
        if "artwork" in tags:
            for artwork in tags["artwork"]:
                image_data = base64.b64decode(artwork["data"])
                audio.tags[f"APIC:{artwork["desc"]}"] = self.artwork_class(
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
            system.LogError(f"Audio file not found: {audio_file}")
            return False

        # Load audio file
        system.LogInfo(f"Removing ID3 tags from {audio_file}")
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

    def get_audio_file_info(self, audio_file, verbose = False, exit_on_failure = False):

        # Check file exists
        if not system.IsPathFile(audio_file):
            system.LogError(f"Audio file not found: {audio_file}")
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
