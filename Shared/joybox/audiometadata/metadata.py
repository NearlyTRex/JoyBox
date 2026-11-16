# Local imports
from joybox.audiometadata.albums import AlbumTagsMixin
from joybox.audiometadata.id3 import Id3TagsMixin
from joybox.audiometadata.mp4 import Mp4TagsMixin
from joybox import programs
from joybox import logger
from joybox import modules
from joybox import paths

# Audio metadata class, reading and writing tags through mutagen with the format
# methods of its mixins
class AudioMetadata(Id3TagsMixin, Mp4TagsMixin, AlbumTagsMixin):

    # Constructor
    def __init__(self):

        # Import mutagen modules
        self.mutagen = modules.import_python_module_package(
            module_path = programs.get_tool_path_config_value("Mutagen", "package_dir"),
            module_name = programs.get_tool_config_value("Mutagen", "package_name"))
        self.mutagen_mp3 = modules.import_python_module_package(
            module_path = programs.get_tool_path_config_value("MutagenMP3", "package_dir"),
            module_name = programs.get_tool_config_value("MutagenMP3", "package_name"))
        self.mutagen_id3 = modules.import_python_module_package(
            module_path = programs.get_tool_path_config_value("MutagenID3", "package_dir"),
            module_name = programs.get_tool_config_value("MutagenID3", "package_name"))
        self.mutagen_mp4 = modules.import_python_module_package(
            module_path = programs.get_tool_path_config_value("MutagenMP4", "package_dir"),
            module_name = programs.get_tool_config_value("MutagenMP4", "package_name"))
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
        if not paths.is_path_file(audio_file):
            logger.log_error(f"Audio file not found: {audio_file}")
            return None

        # Detect format by extension
        ext = paths.get_filename_extension(audio_file).lower()
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
        if not paths.is_path_file(audio_file):
            logger.log_error(f"Audio file not found: {audio_file}")
            return False

        # Detect format by extension
        ext = paths.get_filename_extension(audio_file).lower()
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
        if not paths.is_path_file(audio_file):
            logger.log_error(f"Audio file not found: {audio_file}")
            return False

        # Detect format by extension
        ext = paths.get_filename_extension(audio_file).lower()
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
        if not paths.is_path_file(audio_file):
            return False

        # Detect format by extension
        ext = paths.get_filename_extension(audio_file).lower()
        if ext in [".m4a", ".m4b", ".mp4", ".aac"]:
            return self.has_mp4_tags(audio_file)
        else:
            return self.has_id3_tags(audio_file)

    def get_file_info(self, audio_file, verbose = False, exit_on_failure = False):

        # Check file exists
        if not paths.is_path_file(audio_file):
            logger.log_error(f"Audio file not found: {audio_file}")
            return None

        # Detect format by extension
        ext = paths.get_filename_extension(audio_file).lower()
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
