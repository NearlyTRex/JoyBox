# Imports
import os
import sys
import configparser

# Local imports
import settings
import system

# Open ini file
def OpenIniFile(ini_path):

    # Create config parser
    config = configparser.ConfigParser(interpolation=None)

    # Read ini file
    if os.path.isfile(ini_path):
        config.read(ini_path)
    else:
        config.read_dict(settings.ini_defaults)
        for userdata_section in config.sections():
            for userdata_key in config[userdata_section]:
                config[userdata_section][userdata_key] = system.PromptForValue(userdata_key, config[userdata_section][userdata_key])
        with open(ini_path, "w") as f:
            config.write(f)

    # Return ini values
    ini_values = {}
    for section in config.sections():
        ini_values[section] = {}
        for key, val in config.items(section):
            ini_values[section][key] = val
    return ini_values
