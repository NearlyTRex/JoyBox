# Imports
import os, os.path
import sys
import configparser

# Ini file location
ini_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", ".."))
ini_file = os.path.join(ini_folder, "JoyBox.ini")

# Ini file parser
ini_parser = configparser.ConfigParser()

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
    if HasIniField(section, field):
        return ini_parser[section][field]
    return None

# Get ini integer value
def GetIniIntegerValue(section, field):
    value = GetIniValue(section, field)
    if not value:
        return None
    try:
        return int(value)
    except:
        return None

# Get ini path value
def GetIniPathValue(section, field):
    value = GetIniValue(section, field)
    if not value:
        return None
    return os.path.expandvars(value)
