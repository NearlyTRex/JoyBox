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
        self.config = self.read_from_file(src) if os.path.isfile(src) else {}

        # Add in the default config sections
        updated = False
        for section, defaults in default_config.items():
            if section not in self.config:
                self.config[section] = {}
            if not self.has_section(section):
                self.add_section(section)
            for key, default_value in defaults.items():
                if key not in self.config[section]:
                    self.config[section][key] = util.prompt_for_value(key, default_value)
                    updated = True
                self.set_value(section, key, str(self.config[section][key]))

        # Write config back to file
        if updated or not os.path.isfile(src):
            self.Write(src)

    def copy(self):
        return copy.deepcopy(self)

    def read_from_file(self, src):
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
            util.log_error(f"Error reading the config file '{src}'")
            util.log_error(e)
            return None

    def write_to_file(self, src):
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
            util.log_error(f"Error writing the config file '{src}'")
            util.log_error(e)
            return False

    def has_section(self, section):
        return section in self.config

    def add_section(self, section):
        if self.has_section(section):
            self.config[section] = {}

    def set_value(self, section, key, value):
        if self.has_section(section):
            self.config[section][key] = value

    def get_value(self, section, key, default_value = None):
        return self.config.get(section, {}).get(key, default_value)
