# Opening an audio file for its tags or stream info, shared by the format mixins

# Imports
import os

# Local imports
from joybox import logger
from joybox import paths

# The file opened by open_func, logging the action message when verbose; None, after logging
# the error, when the file is missing or open_func raises error_class
def load_audio_file(audio_file, open_func, error_class, failure_message, action_message, verbose = False, exit_on_failure = False):

    # Check file exists
    if not paths.is_path_file(audio_file):
        logger.log_error("Audio file not found: %s" % audio_file, quit_program = exit_on_failure)
        return None

    # Load audio file
    if verbose:
        logger.log_info(action_message)
    try:
        return open_func(audio_file)
    except error_class as e:
        logger.log_error("%s: %s" % (failure_message, e), quit_program = exit_on_failure)
        return None

# Path, size, bitrate, length, sample rate, channels and tag presence of an opened audio file
def build_audio_file_info(audio_file, audio):
    return {
        "path": audio_file,
        "size": os.path.getsize(audio_file),
        "bitrate": getattr(audio.info, "bitrate", 0),
        "length": getattr(audio.info, "length", 0),
        "sample_rate": getattr(audio.info, "sample_rate", 0),
        "channels": getattr(audio.info, "channels", 0),
        "has_tags": audio.tags is not None
    }
