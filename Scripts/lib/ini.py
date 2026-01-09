# Imports
import os, os.path
import sys
import configparser

# Ini file location - check home directory first, then repo root
ini_home = os.path.join(os.path.expanduser("~"), "JoyBox.ini")
ini_repo = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "JoyBox.ini"))
ini_file = ini_home if os.path.exists(ini_home) else ini_repo

# Ini file parser
ini_parser = configparser.ConfigParser(interpolation=None)

# Check if ini is present
def is_ini_present():
    return os.path.exists(ini_file)

# Get ini sections
def get_ini_sections(throw_exception = True):
    try:
        ini_parser.read(ini_file)
        return ini_parser.sections()
    except:
        if throw_exception:
            raise RuntimeError("Unable to read ini sections [file=%s]" % ini_file)
        return []

# Determine if ini has section
def has_ini_section(section, throw_exception = True):
    try:
        ini_parser.read(ini_file)
        return section in ini_parser
    except:
        if throw_exception:
            raise RuntimeError("Unable to check ini section [file=%s][section=%s]" % (ini_file, section))
        return False

# Determine if ini has field
def has_ini_field(section, field, throw_exception = True):
    try:
        ini_parser.read(ini_file)
        return (section in ini_parser) and (field in ini_parser[section])
    except:
        if throw_exception:
            raise RuntimeError("Unable to check ini field [file=%s][section=%s][field=%s]" % (ini_file, section, field))
        return False

# Get ini value
def get_ini_value(section, field, default_value = None, throw_exception = True):
    try:
        ini_parser.read(ini_file)
        return ini_parser.get(section, field, fallback = default_value)
    except:
        if throw_exception:
            raise RuntimeError("Unable to get ini value [file=%s][section=%s][field=%s]" % (ini_file, section, field))
        return default_value

# Get ini integer value
def get_ini_integer_value(section, field, default_value = None, throw_exception = True):
    try:
        ini_parser.read(ini_file)
        return ini_parser.getint(section, field, fallback = default_value)
    except:
        if throw_exception:
            raise RuntimeError("Unable to get ini integer value [file=%s][section=%s][field=%s]" % (ini_file, section, field))
        return default_value

# Get ini bool value
def get_ini_bool_value(section, field, default_value = None, throw_exception = True):
    try:
        ini_parser.read(ini_file)
        return ini_parser.getboolean(section, field, fallback = default_value)
    except:
        if throw_exception:
            raise RuntimeError("Unable to get ini boolean value [file=%s][section=%s][field=%s]" % (ini_file, section, field))
        return default_value

# Get ini path value
def get_ini_path_value(section, field, default_value = None, throw_exception = True):
    try:
        value = get_ini_value(section, field)
        return os.path.expandvars(value)
    except:
        if throw_exception:
            raise RuntimeError("Unable to get ini path value [file=%s][section=%s][field=%s]" % (ini_file, section, field))
        return default_value

# Get ini list value
def get_ini_list_value(section, field, delimiter = ",", default_value = None, throw_exception = True):
    try:
        value = get_ini_value(section, field)
        return value.split(delimiter)
    except:
        if throw_exception:
            raise RuntimeError("Unable to get ini list value [file=%s][section=%s][field=%s][delimiter=%s]" % (ini_file, section, field, delimiter))
        return default_value
