# Local imports
from joybox import settings

# Settings section for the game mic
SECTION = "UserData.GameMic"

# Matched games record from the silent mic, keep the real mic with its volume
# locked, or are left alone
MODE_SILENT = "silent"
MODE_LOCKED = "locked"
MODE_OFF = "off"
MODES = (MODE_SILENT, MODE_LOCKED, MODE_OFF)

# Configured mode, falling back to silent for an unknown value
def get_mode():
    mode = (settings.get_value(SECTION, "game_mic_mode", throw_exception = False) or MODE_SILENT).strip().lower()
    return mode if mode in MODES else MODE_SILENT

# Comma-separated app names from a field, trimmed, blanks dropped
def get_app_names(field):
    names = settings.get_list_value(SECTION, field, throw_exception = False) or []
    return [name.strip() for name in names if name.strip()]

# Games that keep the real mic, matched by binary or application name
def get_allowed_apps():
    return get_app_names("game_mic_allow")

# Apps never treated as games, matched by binary or application name
def get_protected_apps():
    return get_app_names("game_mic_protect")

# Whether matched games are also kept off every output's volume
def is_output_locked():
    return settings.get_bool_value(SECTION, "game_mic_lock_output", False, throw_exception = False)

# Characters a POSIX extended regex treats specially
REGEX_SPECIAL_CHARS = ".[]()*+?{}|^$\\"

# POSIX regex body that matches a name, ignoring case
def get_case_insensitive_pattern(name):
    pattern = ""
    for char in name:
        if char.lower() != char.upper():
            pattern += "[%s%s]" % (char.lower(), char.upper())
        elif char in REGEX_SPECIAL_CHARS:
            pattern += "\\" + char
        else:
            pattern += char
    return pattern

# POSIX regex that matches any of the names exactly, ignoring case
def get_names_pattern(names):
    return "^(%s)$" % "|".join(get_case_insensitive_pattern(name) for name in names)

# Text quoted for a PipeWire config string
def quote_spa_string(text):
    return '"%s"' % text.replace("\\", "\\\\").replace('"', '\\"')

# Text escaped to sit inside a double-quoted Lua string
def escape_lua_string(text):
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
