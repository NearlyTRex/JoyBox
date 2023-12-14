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
ini_parser = configparser.ConfigParser()

# Check if ini is present
def IsIniPresent():
    return os.path.exists(ini_file)

# Initialize ini file
def InitializeIniFile(verbose = False, exit_on_failure = False):

    # Ignore already existing file
    if IsIniPresent():
        return

    # Get example file
    new_ini_file = None
    if environment.IsWindowsPlatform():
        new_ini_file = os.path.join(ini_folder, "JoyBox.windows.ini.example")
    elif environment.IsLinuxPlatform():
        new_ini_file = os.path.join(ini_folder, "JoyBox.linux.ini.example")

    # Copy file
    if new_ini_file:
        system.CopyFileOrDirectory(
            src = os.path.join(ini_folder, ini_filename),
            dest = ini_file,
            skip_existing = True,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

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

# Get ini bool value
def GetIniBoolValue(section, field):
    value = GetIniValue(section, field)
    if not value:
        return None
    try:
        return bool(value)
    except:
        return None

# Get ini path value
def GetIniPathValue(section, field):
    value = GetIniValue(section, field)
    if not value:
        return None
    return os.path.expandvars(value)

# Get ini list value
def GetIniListValue(section, field, delimiter = ","):
    value = GetIniValue(section, field)
    if not value:
        return None
    return value.split(delimiter)
