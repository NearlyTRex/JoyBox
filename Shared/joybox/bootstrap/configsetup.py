# Creating and rebuilding JoyBox.ini
#
# A new file is the generated defaults plus the answers to a few questions
# about this machine. A rebuilt one keeps every value the old file set, so
# picking up settings added since it was made never loses a personal one, and
# the old file is kept beside it. Values are read as written: a secret
# reference stays a reference and is never resolved here.

# Imports
import configparser
import time

# Local imports
from joybox import default_settings
from joybox import fileops
from joybox import logger
from joybox import prompts
from joybox import serialization

# What this machine does for game streaming
STREAMING_ROLES = ["none", "host", "client"]

###########################################################
# Values
###########################################################

# Read a file's values as written, as {section: {key: value}}
def read_config_values(path):
    text = serialization.read_text_file(path)
    if text is None:
        return None
    parser = configparser.ConfigParser(interpolation = None)
    try:
        parser.read_string(text)
    except configparser.Error as e:
        logger.log_error(f"Unable to parse '{path}': {e}")
        return None
    return {section: dict(parser[section]) for section in parser.sections()}

# Get a value from what has been read, falling back to the default
def get_config_value(values, section, key):
    if key in values.get(section, {}):
        return values[section][key]
    return str(default_settings.ini_defaults.get(section, {}).get(key, ""))

# Set a value
def set_config_value(values, section, key, value):
    values.setdefault(section, {})[key] = value

###########################################################
# Questions
###########################################################

# Get the streaming role the values describe
def get_streaming_role(values):
    if get_config_value(values, "Tools.Sunshine", "sunshine_streaming_host").lower() == "true":
        return "host"
    if get_config_value(values, "Tools.Moonlight", "moonlight_host"):
        return "client"
    return "none"

# Ask what this machine does for game streaming, with the current answers as
# the defaults
def ask_streaming_questions(values):
    role = prompts.prompt_for_choice(
        "Game streaming: is this machine a host (streams its games), a client (plays them on a TV), or none",
        choices = STREAMING_ROLES,
        default_value = get_streaming_role(values))
    set_config_value(values, "Tools.Sunshine", "sunshine_streaming_host", str(role == "host"))
    if role != "client":
        set_config_value(values, "Tools.Moonlight", "moonlight_autostart", "False")
    if role == "host":
        set_config_value(values, "Tools.Sunshine", "sunshine_allowed_subnet", prompts.prompt_for_value(
            "Network clients may stream from",
            get_config_value(values, "Tools.Sunshine", "sunshine_allowed_subnet")))
    if role == "client":
        host = ""
        while not host:
            host = prompts.prompt_for_value(
                "Address of the streaming host",
                get_config_value(values, "Tools.Moonlight", "moonlight_host")) or ""
        set_config_value(values, "Tools.Moonlight", "moonlight_host", host)
        set_config_value(values, "Tools.Moonlight", "moonlight_app", prompts.prompt_for_value(
            "App to start on the host",
            get_config_value(values, "Tools.Moonlight", "moonlight_app")))
        set_config_value(values, "Tools.Moonlight", "moonlight_autostart", str(prompts.prompt_for_confirmation(
            "Start streaming at every login", default_yes = True)))
    return values

###########################################################
# Files
###########################################################

# Create a new file, asking the questions first when there is someone to ask
def create_config(path, interactive):
    values = ask_streaming_questions({}) if interactive else {}
    return default_settings.create_default_config_file(path, values = values)

# Rebuild a file from the current defaults and the values it already holds
def recreate_config(path, interactive):
    values = read_config_values(path)
    if values is None:
        logger.log_error(f"Unable to read '{path}'")
        return False

    # Keep the old file, readable only by its owner since it may hold secrets
    backup_path = "%s.backup-%s" % (path, time.strftime("%Y%m%d-%H%M%S"))
    if not fileops.touch_file(src = backup_path, contents = serialization.read_text_file(path), private = True):
        logger.log_error(f"Unable to back up '{path}' to '{backup_path}'")
        return False
    logger.log_info(f"Backed up '{path}' to '{backup_path}'")

    # Write it back
    if interactive:
        ask_streaming_questions(values)
    return default_settings.create_default_config_file(path, values = values)
