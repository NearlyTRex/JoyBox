# Local imports
from joybox.audiometadata.audiofile import build_audio_file_info, load_audio_file
from joybox import modules
from joybox import paths
from joybox import programs
from joybox import serialization

# Extensions read through the MP4 container; .aac only when the file holds one
mp4_extensions = [".m4a", ".m4b", ".mp4", ".aac"]

# A raw ADTS stream's stream info and standalone ID3 tag, answering the info, tags,
# add_tags, save and delete calls the ID3 methods make on an MP3
class AdtsId3File:

    # Constructor
    def __init__(self, audio_file, id3_class, info, tags):
        self.filename = audio_file
        self.info = info
        self.id3_class = id3_class
        self.tags = tags

    # Start an empty tag, written as a new ID3v2 header on save
    def add_tags(self):
        self.tags = self.id3_class()

    # Write the tag into the file's ID3v2 header, creating it when absent; nothing once deleted
    def save(self):
        if self.tags is not None:
            self.tags.save(self.filename)

    # Strip the ID3v2 header from the file
    def delete(self):
        self.tags.delete(self.filename)
        self.tags = None

# AudioMetadata's .aac handling: telling an MP4 container from a raw ADTS stream
# by its bytes, and reading an ADTS stream's info and ID3 tag
class AdtsTagsMixin:

    # Whether the file has an `ftyp` box at bytes 4..8, the mark of an MP4 container
    def has_mp4_container(self, audio_file):
        return serialization.read_binary_file(audio_file, offset = 4, length = 4) == b"ftyp"

    # Whether the file goes to the MP4 methods: an MP4 extension, and for .aac an MP4 container
    def is_mp4_audio_file(self, audio_file):
        ext = paths.get_filename_extension(audio_file).lower()
        if ext == ".aac":
            return self.has_mp4_container(audio_file)
        return ext in mp4_extensions

    # Whether the file is an .aac without an MP4 container, read as a raw ADTS stream
    def is_adts_audio_file(self, audio_file):
        ext = paths.get_filename_extension(audio_file).lower()
        return ext == ".aac" and not self.has_mp4_container(audio_file)

    # mutagen.aac from the Mutagen tool, loaded on first use and kept
    def get_mutagen_aac(self):
        if self.mutagen_aac is None:
            self.mutagen_aac = modules.import_python_module_package(
                module_path = programs.get_tool_path_config_value("MutagenAAC", "package_dir"),
                module_name = programs.get_tool_config_value("MutagenAAC", "package_name"))
            if self.mutagen_aac is None:
                raise ImportError("Failed to import mutagen.aac")
        return self.mutagen_aac

    # The stream's AAC info and ID3 tag, tags None when it has no ID3 header; raises MutagenError when not AAC
    def open_adts_id3_file(self, audio_file):
        info = self.get_mutagen_aac().AAC(audio_file).info
        try:
            tags = self.id3_class(audio_file)
        except self.mutagen_id3.ID3NoHeaderError:
            tags = None
        return AdtsId3File(audio_file, self.id3_class, info, tags)

    # Path, size, bitrate, length, sample rate, channels and ID3 tag presence of an ADTS stream; None when unreadable
    def get_adts_file_info(self, audio_file, verbose = False, exit_on_failure = False):
        audio = load_audio_file(
            audio_file, self.open_adts_id3_file, self.mutagen.MutagenError, "Failed to get ADTS file info",
            "Reading ADTS file info from %s" % audio_file, verbose = verbose, exit_on_failure = exit_on_failure)
        if audio is None:
            return None
        return build_audio_file_info(audio_file, audio)
