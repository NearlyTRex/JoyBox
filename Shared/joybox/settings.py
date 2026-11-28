# Imports
import os
import configparser
import io
import types

# Local imports
from joybox import secretstore
from joybox import serialization
from joybox import default_settings

# Settings file name and default locations (home preferred, repo-root fallback)
CONFIG_FILENAME = "JoyBox.ini"

# JoyBox.ini in the user's home directory, the preferred location
def get_home_settings_file():
    return os.path.join(os.path.expanduser("~"), CONFIG_FILENAME)

# JoyBox.ini at the repo root, used when the home one is missing
def get_repo_settings_file():
    return os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", CONFIG_FILENAME))

_home_file = get_home_settings_file()
_repo_file = get_repo_settings_file()
# Which settings file is in use, its parsed contents, the file they were read from, and in-memory overrides
_state = types.SimpleNamespace(
    settings_file = _home_file if os.path.exists(_home_file) else _repo_file,
    parser = configparser.ConfigParser(interpolation = None),
    loaded_path = None,
    overlay = {})

###########################################################
# File / state management
###########################################################

# Point reads at another ini file; it is parsed on the next read
def set_settings_file(path):
    _state.settings_file = path
    _state.loaded_path = None

# Path of the ini file reads come from
def get_settings_file():
    return _state.settings_file

# Force a reparse on the next read and drop in-memory overrides and resolved secrets
def reset():
    _state.loaded_path = None
    _state.overlay = {}
    secretstore.clear_resolved_secrets()

def _ensure_loaded():
    if _state.loaded_path != _state.settings_file:
        parser = configparser.ConfigParser(interpolation = None)
        parser.read(_state.settings_file, encoding = "utf-8")
        _state.parser = parser
        _state.loaded_path = _state.settings_file

###########################################################
# Read API
###########################################################

# Whether the selected ini file exists on disk
def is_present():
    return os.path.exists(_state.settings_file)

# Section names in the ini; raises RuntimeError on a read failure unless told not to, then empty
def get_sections(throw_exception = True):
    try:
        _ensure_loaded()
        return _state.parser.sections()
    except (OSError, ValueError, configparser.Error) as e:
        if throw_exception:
            raise RuntimeError("Unable to read settings sections [file=%s]" % _state.settings_file) from e
        return []

# Field names in a section; empty when the section is missing or, not throwing, unreadable
def get_fields(section, throw_exception = True):
    try:
        _ensure_loaded()
        if section not in _state.parser:
            return []
        return list(_state.parser[section].keys())
    except (OSError, ValueError, configparser.Error) as e:
        if throw_exception:
            raise RuntimeError("Unable to read settings fields [file=%s][section=%s]" % (_state.settings_file, section)) from e
        return []

# Whether the ini has the section; False on a read failure when not throwing
def has_section(section, throw_exception = True):
    try:
        _ensure_loaded()
        return section in _state.parser
    except (OSError, ValueError, configparser.Error) as e:
        if throw_exception:
            raise RuntimeError("Unable to check settings section [file=%s][section=%s]" % (_state.settings_file, section)) from e
        return False

# Whether the ini sets the field in the section; False on a read failure when not throwing
def has_field(section, field, throw_exception = True):
    try:
        _ensure_loaded()
        return (section in _state.parser) and (field in _state.parser[section])
    except (OSError, ValueError, configparser.Error) as e:
        if throw_exception:
            raise RuntimeError("Unable to check settings field [file=%s][section=%s][field=%s]" % (_state.settings_file, section, field)) from e
        return False

def _get_shipped_default(section, field):
    value = default_settings.ini_defaults.get(section, {}).get(field)
    if secretstore.is_secret_reference(value):
        return None
    return value

# Override, ini value, or shipped default, with secret references resolved
# Raises RuntimeError on a read failure unless told not to, then returns default_value
def get_value(section, field, default_value = None, throw_exception = True):
    if (section, field) in _state.overlay:
        return secretstore.resolve_value(_state.overlay[(section, field)])
    try:
        _ensure_loaded()
        return secretstore.resolve_value(
            _state.parser.get(section, field, fallback = default_value
                if default_value is not None else _get_shipped_default(section, field)))
    except (OSError, ValueError, configparser.Error) as e:
        if throw_exception:
            raise RuntimeError("Unable to get settings value [file=%s][section=%s][field=%s]" % (_state.settings_file, section, field)) from e
        return default_value

# Get a value as written, a reference left unresolved
def get_raw_value(section, field, default_value = None, throw_exception = True):
    if (section, field) in _state.overlay:
        return _state.overlay[(section, field)]
    try:
        _ensure_loaded()
        return _state.parser.get(section, field, fallback = default_value
            if default_value is not None else _get_shipped_default(section, field))
    except (OSError, ValueError, configparser.Error) as e:
        if throw_exception:
            raise RuntimeError("Unable to get settings value [file=%s][section=%s][field=%s]" % (_state.settings_file, section, field)) from e
        return default_value

def _coerce_integer(value):
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    return int(str(value).strip())

def _coerce_bool(value):
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text not in configparser.ConfigParser.BOOLEAN_STATES:
        raise ValueError("Not a boolean: %s" % value)
    return configparser.ConfigParser.BOOLEAN_STATES[text]

# Field as an int from the override, ini or shipped default; None when none sets it
def get_integer_value(section, field, default_value = None, throw_exception = True):
    try:
        if (section, field) in _state.overlay:
            return _coerce_integer(_state.overlay[(section, field)])
        _ensure_loaded()
        if default_value is None and not _state.parser.has_option(section, field):
            shipped = _get_shipped_default(section, field)
            return None if shipped is None else _coerce_integer(shipped)
        return _state.parser.getint(section, field, fallback = default_value)
    except (OSError, ValueError, configparser.Error) as e:
        if throw_exception:
            raise RuntimeError("Unable to get settings integer value [file=%s][section=%s][field=%s]" % (_state.settings_file, section, field)) from e
        return default_value

# Field as a bool from the override, ini or shipped default; None when none sets it
def get_bool_value(section, field, default_value = None, throw_exception = True):
    try:
        if (section, field) in _state.overlay:
            return _coerce_bool(_state.overlay[(section, field)])
        _ensure_loaded()
        if default_value is None and not _state.parser.has_option(section, field):
            shipped = _get_shipped_default(section, field)
            return None if shipped is None else _coerce_bool(shipped)
        return _state.parser.getboolean(section, field, fallback = default_value)
    except (OSError, ValueError, configparser.Error) as e:
        if throw_exception:
            raise RuntimeError("Unable to get settings boolean value [file=%s][section=%s][field=%s]" % (_state.settings_file, section, field)) from e
        return default_value

# Get a value that must be text; not throwing, anything else reads as unset
def get_text_value(section, field, default_value = None, throw_exception = True):
    value = get_value(section, field, default_value = default_value, throw_exception = throw_exception)
    if value is None or value is default_value or isinstance(value, str):
        return value
    if throw_exception:
        raise RuntimeError("Settings value is not text [file=%s][section=%s][field=%s]" % (_state.settings_file, section, field))
    return default_value

# Text value with environment variables expanded
def get_path_value(section, field, default_value = None, throw_exception = True):
    value = get_text_value(section, field, default_value = default_value, throw_exception = throw_exception)
    return os.path.expandvars(value) if isinstance(value, str) else value

# Text value split on delimiter; a non-text value comes back unsplit
def get_list_value(section, field, delimiter = ",", default_value = None, throw_exception = True):
    value = get_text_value(section, field, default_value = default_value, throw_exception = throw_exception)
    return value.split(delimiter) if isinstance(value, str) else value

###########################################################
# Write API (in-memory overlay; persisted only via save())
###########################################################

# Override a field in memory; it reaches the ini only through save
def set_value(section, field, value):
    _state.overlay[(section, field)] = value

# Write in-memory overrides into the ini file, adding missing sections; False when the write fails
def save():
    _ensure_loaded()
    for (section, field), value in _state.overlay.items():
        if not _state.parser.has_section(section):
            _state.parser.add_section(section)
        _state.parser.set(section, field, str(value))
    contents = io.StringIO()
    _state.parser.write(contents)
    return serialization.write_text_file(_state.settings_file, contents.getvalue())
