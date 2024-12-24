# Imports
import os, os.path
import sys

# Local imports
import config

###########################################################

# Get platforms
def GetPlatforms():
    platforms = []
    for key in config.keys():
        platforms.append(key)
    return platforms

# Check if platform is valid
def IsPlatformValid(platform_name):
    if platform_name:
        return platform_name in config.platforms
    return False

# Get platform section
def GetPlatformSection(platform_name):
    if platform_name and platform_name in config.platforms:
        return config.platforms[platform_name]
    return None

# Get platform value
def GetPlatformValue(platform_name, platform_value):
    if platform_name and platform_name in config.platforms:
        if platform_value and platform_value in config.platforms[platform_name]:
            return config.platforms[platform_name][platform_value]
    return None

###########################################################

# Check if transform platform
def IsTransformPlatform(platform_name):
    if platform_name:
        return platform_name in config.transform_platforms
    return False

# Check if letter platform
def IsLetterPlatform(platform_name):
    if platform_name:
        return platform_name in config.letter_platforms
    return False

###########################################################

# Get addons types
def GetAddonTypes(platform_name):
    return GetPlatformValue(platform_name, config.platform_key_addons)

# Check if updates are possible
def AreUpdatesPossible(platform_name):
    return config.AddonType.UPDATES in GetAddonTypes(platform_name)

# Check if dlc are possible
def AreDLCPossible(platform_name):
    return config.AddonType.DLC in GetAddonTypes(platform_name)

# Check if addons are possible
def AreAddonsPossible(platform_name):
    return len(GetAddonTypes(platform_name)) > 0

###########################################################

# Get launcher types
def GetLauncherTypes(platform_name):
    return GetPlatformValue(platform_name, config.platform_key_launcher)

# Check if no launcher available
def HasNoLauncher(platform_name):
    return config.LaunchType.NONE in GetLauncherTypes(platform_name)

# Check if launched by name
def IsLaunchedByName(platform_name):
    return config.LaunchType.LAUNCH_NAME in GetLauncherTypes(platform_name)

# Check if launched by file
def IsLaunchedByFile(platform_name):
    return config.LaunchType.LAUNCH_FILE in GetLauncherTypes(platform_name)

###########################################################

# Get autofill json keys
def GetAutoFillJsonKeys(platform_name):
    return GetPlatformValue(platform_name, config.platform_key_autofill_json)

# Get fillonce json keys
def GetFillOnceJsonKeys(platform_name):
    return GetPlatformValue(platform_name, config.platform_key_fillonce_json)

# Get merge json keys
def GetMergeJsonKeys(platform_name):
    return GetPlatformValue(platform_name, config.platform_key_merge_json)

# Check if autofill key
def IsAutoFillJsonKey(platform_name, json_key):
    if GetAutoFillJsonKeys(platform_name):
        return json_key in GetAutoFillJsonKeys(platform_name)
    return False

# Check if fillonce key
def IsFillOnceJsonKey(platform_name, json_key):
    if GetFillOnceJsonKeys(platform_name):
        return json_key in GetFillOnceJsonKeys(platform_name)
    return False

# Check if merge key
def IsMergeJsonKey(platform_name, json_key):
    if GetMergeJsonKeys(platform_name):
        return json_key in GetMergeJsonKeys(platform_name)
    return False

###########################################################
