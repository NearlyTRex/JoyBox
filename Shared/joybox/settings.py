# Imports
import os
import configparser
import io
import types

# Local imports
from joybox import secretstore
from joybox import serialization

# Settings file name and default locations (home preferred, repo-root fallback)
CONFIG_FILENAME = "JoyBox.ini"

def get_home_settings_file():
    return os.path.join(os.path.expanduser("~"), CONFIG_FILENAME)

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

def set_settings_file(path):
    _state.settings_file = path
    _state.loaded_path = None

def get_settings_file():
    return _state.settings_file

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

def is_present():
    return os.path.exists(_state.settings_file)

def get_sections(throw_exception = True):
    try:
        _ensure_loaded()
        return _state.parser.sections()
    except Exception as e:
        if throw_exception:
            raise RuntimeError("Unable to read settings sections [file=%s]" % _state.settings_file) from e
        return []

def get_fields(section, throw_exception = True):
    try:
        _ensure_loaded()
        if section not in _state.parser:
            return []
        return list(_state.parser[section].keys())
    except Exception as e:
        if throw_exception:
            raise RuntimeError("Unable to read settings fields [file=%s][section=%s]" % (_state.settings_file, section)) from e
        return []

def has_section(section, throw_exception = True):
    try:
        _ensure_loaded()
        return section in _state.parser
    except Exception as e:
        if throw_exception:
            raise RuntimeError("Unable to check settings section [file=%s][section=%s]" % (_state.settings_file, section)) from e
        return False

def has_field(section, field, throw_exception = True):
    try:
        _ensure_loaded()
        return (section in _state.parser) and (field in _state.parser[section])
    except Exception as e:
        if throw_exception:
            raise RuntimeError("Unable to check settings field [file=%s][section=%s][field=%s]" % (_state.settings_file, section, field)) from e
        return False

def _get_shipped_default(section, field):
    from joybox import default_settings
    value = default_settings.ini_defaults.get(section, {}).get(field)
    if secretstore.is_secret_reference(value):
        return None
    return value

def get_value(section, field, default_value = None, throw_exception = True):
    if (section, field) in _state.overlay:
        return secretstore.resolve_value(_state.overlay[(section, field)])
    try:
        _ensure_loaded()
        return secretstore.resolve_value(
            _state.parser.get(section, field, fallback = default_value
                if default_value is not None else _get_shipped_default(section, field)))
    except Exception as e:
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
    except Exception as e:
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

def get_integer_value(section, field, default_value = None, throw_exception = True):
    try:
        if (section, field) in _state.overlay:
            return _coerce_integer(_state.overlay[(section, field)])
        _ensure_loaded()
        if default_value is None and not _state.parser.has_option(section, field):
            shipped = _get_shipped_default(section, field)
            return None if shipped is None else _coerce_integer(shipped)
        return _state.parser.getint(section, field, fallback = default_value)
    except Exception as e:
        if throw_exception:
            raise RuntimeError("Unable to get settings integer value [file=%s][section=%s][field=%s]" % (_state.settings_file, section, field)) from e
        return default_value

def get_bool_value(section, field, default_value = None, throw_exception = True):
    try:
        if (section, field) in _state.overlay:
            return _coerce_bool(_state.overlay[(section, field)])
        _ensure_loaded()
        if default_value is None and not _state.parser.has_option(section, field):
            shipped = _get_shipped_default(section, field)
            return None if shipped is None else _coerce_bool(shipped)
        return _state.parser.getboolean(section, field, fallback = default_value)
    except Exception as e:
        if throw_exception:
            raise RuntimeError("Unable to get settings boolean value [file=%s][section=%s][field=%s]" % (_state.settings_file, section, field)) from e
        return default_value

def get_path_value(section, field, default_value = None, throw_exception = True):
    try:
        value = get_value(section, field, default_value = default_value, throw_exception = throw_exception)
        if value is None:
            return default_value
        return os.path.expandvars(value)
    except Exception as e:
        if throw_exception:
            raise RuntimeError("Unable to get settings path value [file=%s][section=%s][field=%s]" % (_state.settings_file, section, field)) from e
        return default_value

def get_list_value(section, field, delimiter = ",", default_value = None, throw_exception = True):
    try:
        value = get_value(section, field, default_value = default_value, throw_exception = throw_exception)
        if value is None:
            return default_value
        return value.split(delimiter)
    except Exception as e:
        if throw_exception:
            raise RuntimeError("Unable to get settings list value [file=%s][section=%s][field=%s][delimiter=%s]" % (_state.settings_file, section, field, delimiter)) from e
        return default_value

###########################################################
# Write API (in-memory overlay; persisted only via save())
###########################################################

def set_value(section, field, value):
    _state.overlay[(section, field)] = value

def save():
    _ensure_loaded()
    for (section, field), value in _state.overlay.items():
        if not _state.parser.has_section(section):
            _state.parser.add_section(section)
        _state.parser.set(section, field, str(value))
    contents = io.StringIO()
    _state.parser.write(contents)
    return serialization.write_text_file(_state.settings_file, contents.getvalue())
