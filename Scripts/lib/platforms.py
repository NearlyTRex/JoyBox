# Imports
import os, os.path
import sys

# Local imports
import config

###########################################################

# Check if platform is valid
def is_platform_valid(platform_type):
    if platform_type:
        return platform_type in config.platforms
    return False

# Get platform section
def get_platform_section(platform_type):
    if platform_type and platform_type in config.platforms:
        return config.platforms[platform_type]
    return None

# Get platform value
def get_platform_value(platform_type, platform_key):
    if platform_type and platform_type in config.platforms:
        if platform_key and platform_key in config.platforms[platform_type]:
            return config.platforms[platform_type][platform_key]
    return None

###########################################################

# Check if transform platform
def is_transform_platform(platform_type):
    if platform_type:
        return platform_type in config.transform_platforms
    return False

# Check if letter platform
def is_letter_platform(platform_type):
    if platform_type:
        return platform_type in config.letter_platforms
    return False

###########################################################

# Get addons types
def get_addon_types(platform_type):
    return get_platform_value(platform_type, config.platform_key_addons)

# Check if updates are possible
def are_updates_possible(platform_type):
    return config.AddonType.UPDATES in get_addon_types(platform_type)

# Check if dlc are possible
def are_dlc_possible(platform_type):
    return config.AddonType.DLC in get_addon_types(platform_type)

# Check if addons are possible
def are_addons_possible(platform_type):
    return len(get_addon_types(platform_type)) > 0

###########################################################

# Get launcher types
def get_launcher_types(platform_type):
    return get_platform_value(platform_type, config.platform_key_launcher)

# Check if no launcher available
def has_no_launcher(platform_type):
    return config.LaunchType.NO_LAUNCHER in get_launcher_types(platform_type)

# Check if launched by name
def is_launched_by_name(platform_type):
    return config.LaunchType.LAUNCH_NAME in get_launcher_types(platform_type)

# Check if launched by file
def is_launched_by_file(platform_type):
    return config.LaunchType.LAUNCH_FILE in get_launcher_types(platform_type)

###########################################################

# Get autofill json keys
def get_autofill_json_keys(platform_type):
    return get_platform_value(platform_type, config.platform_key_autofill_json)

# Get fillonce json keys
def get_fillonce_json_keys(platform_type):
    return get_platform_value(platform_type, config.platform_key_fillonce_json)

# Get merge json keys
def get_merge_json_keys(platform_type):
    return get_platform_value(platform_type, config.platform_key_merge_json)

# Check if autofill key
def is_autofill_json_key(platform_type, json_key):
    if get_autofill_json_keys(platform_type):
        return json_key in get_autofill_json_keys(platform_type)
    return False

# Check if fillonce key
def is_fillonce_json_key(platform_type, json_key):
    if get_fillonce_json_keys(platform_type):
        return json_key in get_fillonce_json_keys(platform_type)
    return False

# Check if merge key
def is_merge_json_key(platform_type, json_key):
    if get_merge_json_keys(platform_type):
        return json_key in get_merge_json_keys(platform_type)
    return False

###########################################################
