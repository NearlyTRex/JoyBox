# Unified user configuration.
#
# Reads ~/JoyBox.ini (repo-root JoyBox.ini fallback), the single settings file
# shared by both the Scripts and Bootstrap halves of the repo. Replaces the
# former Scripts `ini` singleton and the Bootstrap `Configuration` object.
#
# Access is via module-level functions (a process-global singleton). Reads are
# cached after first load. `set_value` records an in-memory overlay that is NOT
# persisted unless `save()` is called explicitly — this preserves Bootstrap's
# only runtime mutation (UserData.General.environment_type), which was always
# ephemeral.

# Imports
import os
import configparser

# Default settings-file resolution (home preferred, repo-root fallback)
_home_file = os.path.join(os.path.expanduser("~"), "JoyBox.ini")
_repo_file = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "JoyBox.ini"))

_settings_file = _home_file if os.path.exists(_home_file) else _repo_file
_parser = configparser.ConfigParser(interpolation = None)
_loaded_path = None
_overlay = {}

###########################################################
# File / state management
###########################################################

def set_settings_file(path):
    global _settings_file, _loaded_path
    _settings_file = path
    _loaded_path = None

def get_settings_file():
    return _settings_file

def reset():
    global _loaded_path, _overlay
    _loaded_path = None
    _overlay = {}

def _ensure_loaded():
    global _parser, _loaded_path
    if _loaded_path != _settings_file:
        parser = configparser.ConfigParser(interpolation = None)
        parser.read(_settings_file)
        _parser = parser
        _loaded_path = _settings_file

###########################################################
# Read API
###########################################################

def is_present():
    return os.path.exists(_settings_file)

def get_sections(throw_exception = True):
    try:
        _ensure_loaded()
        return _parser.sections()
    except:
        if throw_exception:
            raise RuntimeError("Unable to read settings sections [file=%s]" % _settings_file)
        return []

def has_section(section, throw_exception = True):
    try:
        _ensure_loaded()
        return section in _parser
    except:
        if throw_exception:
            raise RuntimeError("Unable to check settings section [file=%s][section=%s]" % (_settings_file, section))
        return False

def has_field(section, field, throw_exception = True):
    try:
        _ensure_loaded()
        return (section in _parser) and (field in _parser[section])
    except:
        if throw_exception:
            raise RuntimeError("Unable to check settings field [file=%s][section=%s][field=%s]" % (_settings_file, section, field))
        return False

def get_value(section, field, default_value = None, throw_exception = True):
    if (section, field) in _overlay:
        return _overlay[(section, field)]
    try:
        _ensure_loaded()
        return _parser.get(section, field, fallback = default_value)
    except:
        if throw_exception:
            raise RuntimeError("Unable to get settings value [file=%s][section=%s][field=%s]" % (_settings_file, section, field))
        return default_value

def get_integer_value(section, field, default_value = None, throw_exception = True):
    if (section, field) in _overlay:
        return _overlay[(section, field)]
    try:
        _ensure_loaded()
        return _parser.getint(section, field, fallback = default_value)
    except:
        if throw_exception:
            raise RuntimeError("Unable to get settings integer value [file=%s][section=%s][field=%s]" % (_settings_file, section, field))
        return default_value

def get_bool_value(section, field, default_value = None, throw_exception = True):
    if (section, field) in _overlay:
        return _overlay[(section, field)]
    try:
        _ensure_loaded()
        return _parser.getboolean(section, field, fallback = default_value)
    except:
        if throw_exception:
            raise RuntimeError("Unable to get settings boolean value [file=%s][section=%s][field=%s]" % (_settings_file, section, field))
        return default_value

def get_path_value(section, field, default_value = None, throw_exception = True):
    try:
        value = get_value(section, field, default_value = default_value, throw_exception = throw_exception)
        if value is None:
            return default_value
        return os.path.expandvars(value)
    except:
        if throw_exception:
            raise RuntimeError("Unable to get settings path value [file=%s][section=%s][field=%s]" % (_settings_file, section, field))
        return default_value

def get_list_value(section, field, delimiter = ",", default_value = None, throw_exception = True):
    try:
        value = get_value(section, field, default_value = default_value, throw_exception = throw_exception)
        if value is None:
            return default_value
        return value.split(delimiter)
    except:
        if throw_exception:
            raise RuntimeError("Unable to get settings list value [file=%s][section=%s][field=%s][delimiter=%s]" % (_settings_file, section, field, delimiter))
        return default_value

###########################################################
# Write API (in-memory overlay; persisted only via save())
###########################################################

def set_value(section, field, value):
    _overlay[(section, field)] = value

def save():
    _ensure_loaded()
    for (section, field), value in _overlay.items():
        if not _parser.has_section(section):
            _parser.add_section(section)
        _parser.set(section, field, str(value))
    with open(_settings_file, "w") as f:
        _parser.write(f)

###########################################################
# Backwards-compatible aliases (former Scripts `ini` API)
###########################################################

get_ini_value = get_value
get_ini_integer_value = get_integer_value
get_ini_bool_value = get_bool_value
get_ini_path_value = get_path_value
get_ini_list_value = get_list_value
has_ini_section = has_section
has_ini_field = has_field
get_ini_sections = get_sections
is_ini_present = is_present
