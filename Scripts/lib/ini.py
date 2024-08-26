# Imports
import os, os.path
import sys
import configparser

# Ini file location
ini_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", ".."))
ini_file = os.path.join(ini_folder, "JoyBox.ini")

# Ini file parser
ini_parser = configparser.ConfigParser(interpolation=None)

# Check if ini is present
def IsIniPresent():
    return os.path.exists(ini_file)

# Get ini sections
def GetIniSections():
    try:
        ini_parser.read(ini_file)
        return ini_parser.sections()
    except:
        raise RuntimeError("Unable to read ini sections [file=%s]" % ini_file)

# Determine if ini has section
def HasIniSection(section):
    try:
        ini_parser.read(ini_file)
        return section in ini_parser
    except:
        raise RuntimeError("Unable to check ini section [file=%s][section=%s]" % (ini_file, section))

# Determine if ini has field
def HasIniField(section, field):
    try:
        ini_parser.read(ini_file)
        return (section in ini_parser) and (field in ini_parser[section])
    except:
        raise RuntimeError("Unable to check ini field [file=%s][section=%s][field=%s]" % (ini_file, section, field))

# Get ini value
def GetIniValue(section, field):
    try:
        ini_parser.read(ini_file)
        return ini_parser[section][field]
    except:
        raise RuntimeError("Unable to get ini value [file=%s][section=%s][field=%s]" % (ini_file, section, field))

# Get ini integer value
def GetIniIntegerValue(section, field):
    try:
        value = GetIniValue(section, field)
        return int(value)
    except:
        raise RuntimeError("Unable to get ini integer value [file=%s][section=%s][field=%s]" % (ini_file, section, field))

# Get ini bool value
def GetIniBoolValue(section, field):
    try:
        value = GetIniValue(section, field)
        return value == "True"
    except:
        raise RuntimeError("Unable to get ini boolean value [file=%s][section=%s][field=%s]" % (ini_file, section, field))

# Get ini path value
def GetIniPathValue(section, field):
    try:
        value = GetIniValue(section, field)
        return os.path.expandvars(value)
    except:
        raise RuntimeError("Unable to get ini path value [file=%s][section=%s][field=%s]" % (ini_file, section, field))

# Get ini list value
def GetIniListValue(section, field, delimiter = ","):
    try:
        value = GetIniValue(section, field)
        return value.split(delimiter)
    except:
        raise RuntimeError("Unable to get ini list value [file=%s][section=%s][field=%s][delimiter=%s]" % (ini_file, section, field, delimiter))
