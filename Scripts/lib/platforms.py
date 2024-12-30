# Imports
import os, os.path
import sys

# Local imports
import config

###########################################################

# Check if platform is valid
def IsPlatformValid(platform_type):
    if platform_type:
        return platform_type in config.platforms
    return False

# Get platform section
def GetPlatformSection(platform_type):
    if platform_type and platform_type in config.platforms:
        return config.platforms[platform_type]
    return None

# Get platform value
def GetPlatformValue(platform_type, platform_key):
    if platform_type and platform_type in config.platforms:
        if platform_key and platform_key in config.platforms[platform_type]:
            return config.platforms[platform_type][platform_key]
    return None

###########################################################

# Check if transform platform
def IsTransformPlatform(platform_type):
    if platform_type:
        return platform_type in config.transform_platforms
    return False

# Check if letter platform
def IsLetterPlatform(platform_type):
    if platform_type:
        return platform_type in config.letter_platforms
    return False

###########################################################

# Get addons types
def GetAddonTypes(platform_type):
    return GetPlatformValue(platform_type, config.platform_key_addons)

# Check if updates are possible
def AreUpdatesPossible(platform_type):
    return config.AddonType.UPDATES in GetAddonTypes(platform_type)

# Check if dlc are possible
def AreDLCPossible(platform_type):
    return config.AddonType.DLC in GetAddonTypes(platform_type)

# Check if addons are possible
def AreAddonsPossible(platform_type):
    return len(GetAddonTypes(platform_type)) > 0

###########################################################

# Get launcher types
def GetLauncherTypes(platform_type):
    return GetPlatformValue(platform_type, config.platform_key_launcher)

# Check if no launcher available
def HasNoLauncher(platform_type):
    return config.LaunchType.NO_LAUNCHER in GetLauncherTypes(platform_type)

# Check if launched by name
def IsLaunchedByName(platform_type):
    return config.LaunchType.LAUNCH_NAME in GetLauncherTypes(platform_type)

# Check if launched by file
def IsLaunchedByFile(platform_type):
    return config.LaunchType.LAUNCH_FILE in GetLauncherTypes(platform_type)

###########################################################

# Get autofill json keys
def GetAutoFillJsonKeys(platform_type):
    return GetPlatformValue(platform_type, config.platform_key_autofill_json)

# Get fillonce json keys
def GetFillOnceJsonKeys(platform_type):
    return GetPlatformValue(platform_type, config.platform_key_fillonce_json)

# Get merge json keys
def GetMergeJsonKeys(platform_type):
    return GetPlatformValue(platform_type, config.platform_key_merge_json)

# Check if autofill key
def IsAutoFillJsonKey(platform_type, json_key):
    if GetAutoFillJsonKeys(platform_type):
        return json_key in GetAutoFillJsonKeys(platform_type)
    return False

# Check if fillonce key
def IsFillOnceJsonKey(platform_type, json_key):
    if GetFillOnceJsonKeys(platform_type):
        return json_key in GetFillOnceJsonKeys(platform_type)
    return False

# Check if merge key
def IsMergeJsonKey(platform_type, json_key):
    if GetMergeJsonKeys(platform_type):
        return json_key in GetMergeJsonKeys(platform_type)
    return False

###########################################################
