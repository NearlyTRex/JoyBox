# Imports
import os
import sys
import copy
import configparser

# Local imports
import util

class Configuration:
    def __init__(self, src, default_config = None):

        # Check for default config
        if not default_config:
            default_config = {}

        # Load current config if it exists
        self.config = self.ReadFromFile(src) if os.path.isfile(src) else {}

        # Add in the default config sections
        updated = False
        for section, defaults in default_config.items():
            if section not in self.config:
                self.config[section] = {}
            if not self.HasSection(section):
                self.AddSection(section)
            for key, default_value in defaults.items():
                if key not in self.config[section]:
                    self.config[section][key] = util.PromptForValue(key, default_value)
                    updated = True
                self.SetValue(section, key, str(self.config[section][key]))

        # Write config back to file
        if updated or not os.path.isfile(src):
            self.Write(src)

    def Copy(self):
        return copy.deepcopy(self)

    def ReadFromFile(self, src):
        try:
            result = {}
            self.parser = configparser.ConfigParser(interpolation = None)
            self.parser.read(src)
            for section in self.parser.sections():
                section_dict = {}
                for key, value in self.parser.items(section):
                    if value.lower() in ["true", "false"]:
                        section_dict[key] = self.parser.getboolean(section, key)
                    else:
                        section_dict[key] = value
                result[section] = section_dict
            return result
        except Exception as e:
            util.LogError(f"Error reading the config file '{src}'")
            util.LogError(e)
            return None

    def WriteToFile(self, src):
        try:
            self.parser = configparser.ConfigParser(interpolation=None)
            for section, items in self.config.items():
                if not self.parser.has_section(section):
                    self.parser.add_section(section)
                for key, value in items.items():
                    self.parser.set(section, key, str(value))
            with open(src, "w") as f:
                self.parser.write(f)
            return True
        except Exception as e:
            util.LogError(f"Error writing the config file '{src}'")
            util.LogError(e)
            return False

    def HasSection(self, section):
        return section in self.config

    def AddSection(self, section):
        if self.HasSection(section):
            self.config[section] = {}

    def SetValue(self, section, key, value):
        if self.HasSection(section):
            self.config[section][key] = value

    def GetValue(self, section, key, default_value = None):
        return self.config.get(section, {}).get(key, default_value)
