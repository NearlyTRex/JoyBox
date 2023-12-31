# Imports
import os, os.path
import sys
import configparser

# Local imports
import config
import system
import environment

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
    ini_parser.read(ini_file)
    return ini_parser.sections()

# Determine if ini has section
def HasIniSection(section):
    ini_parser.read(ini_file)
    return section in ini_parser

# Determine if ini has field
def HasIniField(section, field):
    ini_parser.read(ini_file)
    return (section in ini_parser) and (field in ini_parser[section])

# Get ini value
def GetIniValue(section, field):
    ini_parser.read(ini_file)
    system.AssertCondition(
        condition = HasIniField(section, field),
        description = "No ini value found at [%s][%s]" % (section, field))
    return ini_parser[section][field]

# Get ini integer value
def GetIniIntegerValue(section, field):
    value = GetIniValue(section, field)
    system.AssertIsCastableToInt(
        var_value = value,
        var_name = "Ini[%s][%s]" % (section, field))
    return int(value)

# Get ini bool value
def GetIniBoolValue(section, field):
    value = GetIniValue(section, field)
    system.AssertIsCastableToBool(
        var_value = value,
        var_name = "Ini[%s][%s]" % (section, field))
    return value == "True"

# Get ini path value
def GetIniPathValue(section, field):
    value = GetIniValue(section, field)
    system.AssertIsValidPath(
        var_value = value,
        var_name = "Ini[%s][%s]" % (section, field))
    return os.path.expandvars(value)

# Get ini list value
def GetIniListValue(section, field, delimiter = ","):
    value = GetIniValue(section, field)
    return value.split(delimiter)
