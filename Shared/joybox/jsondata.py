# Imports
import copy

# Local imports
from joybox import config
from joybox import datautils
from joybox import platforms

# General json data class
class JsonData:

    # Constructor
    def __init__(self, json_data = None, json_platform = None):
        self.json_data = json_data if json_data is not None else {}
        self.json_platform = json_platform

    # Deep copy of the whole object, data and platform
    def copy(self):
        return copy.deepcopy(self)

    # The wrapped dict itself, so changes to it change this object
    def get_data(self):
        return self.json_data

    # Deep copy of the wrapped dict, safe to modify
    def get_data_copy(self):
        return copy.deepcopy(self.json_data)

    # Platform whose key rules decide how fill_value treats each key
    def get_platform(self):
        return self.json_platform

    # Replace the wrapped dict
    def set_data(self, json_data):
        self.json_data = json_data

    # Replace the platform whose key rules fill_value applies
    def set_platform(self, json_platform):
        self.json_platform = json_platform

    # Top-level key view of the wrapped dict
    def get_keys(self):
        return self.json_data.keys()

    # Check if key is present
    def has_key(self, key):
        try:
            return key in self.json_data
        except (TypeError, AttributeError):
            return False

    # Check if subkey is present
    def has_subkey(self, key, subkey):
        try:
            return subkey in self.json_data[key]
        except (KeyError, IndexError, TypeError, AttributeError):
            return False

    # Top-level value for a key, or the default when absent or the data is not indexable
    def get_value(self, key, default_value = None):
        try:
            return self.json_data[key]
        except (KeyError, IndexError, TypeError):
            return default_value

    # Nested value data[key][subkey], or the default when either level is absent
    def get_subvalue(self, key, subkey, default_value = None):
        try:
            return self.json_data[key][subkey]
        except (KeyError, IndexError, TypeError):
            return default_value

    # Store a top-level value; False when the data cannot take it
    def set_value(self, key, value):
        try:
            self.json_data[key] = value
            return True
        except (TypeError, AttributeError):
            return False

    # Store data[key][subkey], creating the key's dict when absent; False when the data cannot take it
    def set_subvalue(self, key, subkey, value):
        try:
            if not self.has_key(key):
                self.json_data[key] = {}
            self.json_data[key][subkey] = value
            return True
        except (KeyError, IndexError, TypeError, AttributeError):
            return False

    # Set, set-if-absent or additively merge a value, as the platform marks the key autofill, fill-once or merge; other keys are left alone
    def fill_value(self, key, value):
        if platforms.is_autofill_json_key(self.json_platform, key):
            self.set_value(key, value)
        elif platforms.is_fillonce_json_key(self.json_platform, key):
            if not self.has_key(key):
                self.set_value(key, value)
        elif platforms.is_merge_json_key(self.json_platform, key):
            self.set_value(key, datautils.merge_data(
                data1 = self.get_value(key),
                data2 = value,
                merge_type = config.MergeType.SAFE_ADDITIVE))

    # Set, set-if-absent or additively merge data[key][subkey] by the platform's rule for the subkey; other subkeys are left alone
    def fill_subvalue(self, key, subkey, value):
        if platforms.is_autofill_json_key(self.json_platform, subkey):
            self.set_subvalue(key, subkey, value)
        elif platforms.is_fillonce_json_key(self.json_platform, subkey):
            if not self.has_subkey(key, subkey):
                self.set_subvalue(key, subkey, value)
        elif platforms.is_merge_json_key(self.json_platform, subkey):
            self.set_subvalue(key, subkey, datautils.merge_data(
                data1 = self.get_subvalue(key, subkey),
                data2 = value,
                merge_type = config.MergeType.SAFE_ADDITIVE))
