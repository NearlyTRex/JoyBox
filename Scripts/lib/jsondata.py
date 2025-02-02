# Imports
import os, os.path
import sys
import copy

# Local imports
import config
import platforms
import system

# General json data class
class JsonData:

    # Constructor
    def __init__(self, json_data = None, json_platform = None):
        self.json_data = json_data if json_data is not None else {}
        self.json_platform = json_platform

    # Copy method
    def copy(self):
        return JsonData(
            json_data = copy.deepcopy(self.json_data),
            json_platform = copy.deepcopy(self.json_platform))

    # Get data
    def get_data(self):
        return self.json_data

    # Get data copy
    def get_data_copy(self):
        return copy.deepcopy(self.json_data)

    # Get platform
    def get_platform(self):
        return self.json_platform

    # Set data
    def set_data(self, json_data):
        self.json_data = json_data

    # Set platform
    def set_platform(self, json_platform):
        self.json_platform = json_platform

    # Get keys
    def get_keys(self):
        return self.json_data.keys()

    # Check if key is present
    def has_key(self, key):
        try:
            return key in self.json_data
        except:
            return False

    # Check if subkey is present
    def has_subkey(self, key, subkey):
        try:
            return subkey in self.json_data[key]
        except:
            return False

    # Get value
    def get_value(self, key, default_value = None):
        try:
            return self.json_data[key]
        except:
            return default_value

    # Get subvalue
    def get_subvalue(self, key, subkey, default_value = None):
        try:
            return self.json_data[key][subkey]
        except:
            return default_value

    # Set value
    def set_value(self, key, value):
        try:
            self.json_data[key] = value
        except:
            return

    # Set subvalue
    def set_subvalue(self, key, subkey, value):
        try:
            self.json_data[key][subkey] = value
        except:
            return

    # Fill value
    def fill_value(self, key, value):
        if platforms.IsAutoFillJsonKey(self.json_platform, key):
            self.set_value(key, value)
        elif platforms.IsFillOnceJsonKey(self.json_platform, key):
            if not self.has_key(key):
                self.set_value(key, value)
        elif platforms.IsMergeJsonKey(self.json_platform, key):
            self.set_value(key, system.MergeData(
                data1 = self.get_value(key),
                data2 = value,
                merge_type = config.MergeType.SAFE_ADDITIVE))

    # Fill subvalue
    def fill_subvalue(self, key, subkey, value):
        if platforms.IsAutoFillJsonKey(self.json_platform, subkey):
            self.set_subvalue(key, subkey, value)
        elif platforms.IsFillOnceJsonKey(self.json_platform, subkey):
            if not self.has_subkey(key, subkey):
                self.set_subvalue(key, subkey, value)
        elif platforms.IsMergeJsonKey(self.json_platform, subkey):
            self.set_subvalue(key, subkey, system.MergeData(
                data1 = self.get_subvalue(key, subkey),
                data2 = value,
                merge_type = config.MergeType.SAFE_ADDITIVE))
