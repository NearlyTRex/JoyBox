# Imports
import os, os.path
import sys

# Local imports
import platforms

# General json data class
class JsonData:

    # Constructor
    def __init__(self, json_data, json_platform):
        self.json_data = json_data
        self.json_platform = json_platform

    # Set json value
    def SetJsonValue(self, json_key, json_value):
        self.json_data[json_key] = json_value

    # Get json value
    def GetJsonValue(self, json_key, default_value = None):
        if json_key in self.json_data:
            return self.json_data[json_key]
        return default_value

    # Fill json value
    def FillJsonValue(self, json_key, json_value):
        if platforms.IsAutoFillJsonKey(self.json_platform, json_key):
            self.json_data[json_key] = json_value
        elif platforms.IsFillOnceJsonKey(self.json_platform, json_key):
            if json_key not in self.json_data:
                self.json_data[json_key] = json_value

    # Get json data
    def GetJsonData(self):
        return self.json_data
