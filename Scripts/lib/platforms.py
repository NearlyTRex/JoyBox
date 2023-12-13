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
    return platform_name in config.platforms

# Get platform section
def GetPlatformSection(platform_name):
    if platform_name in config.platforms:
        return config.platforms[platform_name]
    return None

# Get platform value
def GetPlatformValue(platform_name, platform_value):
    if platform_name in config.platforms:
        if platform_value in config.platforms[platform_name]:
            return config.platforms[platform_name][platform_value]
    return None

###########################################################

# Get transform types
def GetTransformTypes(platform_name):
    return GetPlatformValue(platform_name, config.platform_key_transforms)

# Check if platform has transform type
def HasTransformType(platform_name, transform_type):
    return transform_type in GetTransformTypes(platform_name)

# Check if transforms are required
def AreTransformsRequired(platform_name):
    return len(GetTransformTypes(platform_name)) == 0

###########################################################

# Get addons types
def GetAddonTypes(platform_name):
    return GetPlatformValue(platform_name, config.platform_key_addons)

# Check if updates are possible
def AreUpdatesPossible(platform_name):
    return config.addon_type_updates in GetAddonTypes(platform_name)

# Check if dlc are possible
def AreDLCPossible(platform_name):
    return config.addon_type_dlc in GetAddonTypes(platform_name)

# Check if addons are possible
def AreAddonsPossible(platform_name):
    return len(GetAddonTypes(platform_name)) == 0

###########################################################

# Get launcher types
def GetLauncherTypes(platform_name):
    return GetPlatformValue(platform_name, config.platform_key_launcher)

# Check if no launcher available
def HasNoLauncher(platform_name):
    return config.launch_type_none in GetLauncherTypes(platform_name)

# Check if launched by name
def IsLaunchedByName(platform_name):
    return config.launch_type_name in GetLauncherTypes(platform_name)

# Check if launched by file
def IsLaunchedByFile(platform_name):
    return config.launch_type_file in GetLauncherTypes(platform_name)

###########################################################
