# Imports
import os, os.path
import sys

# Local imports
import config
import system
import jsondata

# Program
class Program(jsondata.JsonData):

    # Constructor
    def __init__(self, json_data = None, json_platform = None):
        super().__init__(json_data, json_platform)

    # Executable
    def set_exe(self, value):
        self.set_value(config.program_key_exe, value)
    def get_exe(self):
        return self.get_value(config.program_key_exe)

    # Current working directory
    def set_cwd(self, value):
        self.set_value(config.program_key_cwd, value)
    def get_cwd(self):
        return self.get_value(config.program_key_cwd)

    # Environment variables
    def set_env(self, value):
        self.set_value(config.program_key_env, value)
    def get_env(self):
        return self.get_value(config.program_key_env)

    # Arguments
    def set_args(self, value):
        self.set_value(config.program_key_args, value)
    def get_args(self):
        return self.get_value(config.program_key_args)

    # Windows version
    def set_winver(self, value):
        self.set_value(config.program_key_winver, value)
    def get_winver(self):
        return self.get_value(config.program_key_winver)

    # Tricks
    def set_tricks(self, value):
        self.set_value(config.program_key_tricks, value)
    def get_tricks(self):
        return self.get_value(config.program_key_tricks)

    # Overrides
    def set_overrides(self, value):
        self.set_value(config.program_key_overrides, value)
    def get_overrides(self):
        return self.get_value(config.program_key_overrides)

    # Desktop resolution
    def set_desktop(self, value):
        self.set_value(config.program_key_desktop, value)
    def get_desktop(self):
        return self.get_value(config.program_key_desktop)

    # Installer type
    def set_installer_type(self, value):
        self.set_value(config.program_key_installer_type, value)
    def get_installer_type(self):
        return self.get_value(config.program_key_installer_type)

    # Serial number/key
    def set_serial(self, value):
        self.set_value(config.program_key_serial, value)
    def get_serial(self):
        return self.get_value(config.program_key_serial)

    # Is shell program
    def set_is_shell(self, value):
        self.set_value(config.program_key_is_shell, value)
    def is_shell(self):
        return self.get_value(config.program_key_is_shell, False)

    # Is 32-bit program
    def set_is_32_bit(self, value):
        self.set_value(config.program_key_is_32_bit, value)
    def is_32_bit(self):
        return self.get_value(config.program_key_is_32_bit, False)

    # Is dos program
    def set_is_dos(self, value):
        self.set_value(config.program_key_is_dos, value)
    def is_dos(self):
        return self.get_value(config.program_key_is_dos, False)

    # Is windows 3.1 program
    def set_is_win31(self, value):
        self.set_value(config.program_key_is_win31, value)
    def is_win31(self):
        return self.get_value(config.program_key_is_win31, False)

    # Is scumm program
    def set_is_scumm(self, value):
        self.set_value(config.program_key_is_scumm, value)
    def is_scumm(self):
        return self.get_value(config.program_key_is_scumm, False)

# Program step
class ProgramStep(jsondata.JsonData):

    # Constructor
    def __init__(self, json_data = None, json_platform = None):
        super().__init__(json_data, json_platform)

    # From
    def set_from(self, value):
        self.set_value(config.program_step_key_from, value)
    def get_from(self):
        return self.get_value(config.program_step_key_from, "")

    # To
    def set_to(self, value):
        self.set_value(config.program_step_key_to, value)
    def get_to(self):
        return self.get_value(config.program_step_key_to, "")

    # Dir
    def set_dir(self, value):
        self.set_value(config.program_step_key_dir, value)
    def get_dir(self):
        return self.get_value(config.program_step_key_dir, "")

    # Type
    def set_type(self, value):
        self.set_value(config.program_step_key_type, value)
    def get_type(self):
        return self.get_value(config.program_step_key_type)

    # Skip existing
    def set_skip_existing(self, value):
        self.set_value(config.program_step_key_skip_existing, value)
    def skip_existing(self):
        return self.get_value(config.program_step_key_skip_existing, False)

    # Skip identical
    def set_skip_identical(self, value):
        self.set_value(config.program_step_key_skip_identical, value)
    def skip_identical(self):
        return self.get_value(config.program_step_key_skip_identical, False)

# Search result
class SearchResult(jsondata.JsonData):

    # Constructor
    def __init__(self, json_data = None, json_platform = None):
        super().__init__(json_data, json_platform)

    # Id
    def set_id(self, value):
        self.set_value(config.search_result_key_id, value)
    def get_id(self):
        return self.get_value(config.search_result_key_id)

    # Title
    def set_title(self, value):
        self.set_value(config.search_result_key_title, value)
    def get_title(self):
        return self.get_value(config.search_result_key_title)

    # Description
    def set_description(self, value):
        self.set_value(config.search_result_key_description, value)
    def get_description(self):
        return self.get_value(config.search_result_key_description, self.get_title())

    # Url
    def set_url(self, value):
        self.set_value(config.search_result_key_url, value)
    def get_url(self):
        return self.get_value(config.search_result_key_url)

    # Date
    def set_date(self, value):
        self.set_value(config.search_result_key_date, value)
    def get_date(self):
        return self.get_value(config.search_result_key_date)

    # Relevance
    def set_relevance(self, value):
        self.set_value(config.search_result_key_relevance, value)
    def get_relevance(self):
        return self.get_value(config.search_result_key_relevance)

    # Data
    def set_data(self, value):
        self.set_value(config.search_result_key_data, value)
    def get_data(self):
        return self.get_value(config.search_result_key_data)

# Asset search result
class AssetSearchResult(SearchResult):

    # Constructor
    def __init__(self, json_data = None, json_platform = None):
        super().__init__(json_data, json_platform)

    # Mime
    def set_mime(self, value):
        self.set_value(config.asset_key_mime, value)
    def get_mime(self):
        return self.get_value(config.asset_key_mime)

    # Width
    def set_width(self, value):
        self.set_value(config.asset_key_width, value)
    def get_width(self):
        return self.get_value(config.asset_key_width)

    # Height
    def set_height(self, value):
        self.set_value(config.asset_key_height, value)
    def get_height(self):
        return self.get_value(config.asset_key_height)

    # Duration
    def set_duration(self, value):
        self.set_value(config.asset_key_duration, value)
    def get_duration(self):
        return self.get_value(config.asset_key_duration)
