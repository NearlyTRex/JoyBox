# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__)))
sys.path.append(lib_folder)
import config

# Get all categories
def GetAllCategories():
    categories = []
    for section in config.platforms.values():
        categories.append(section[config.platforms.key_category])
    return categories

# Get all subcategories
def GetAllSubcategories():
    subcategories = []
    for section in config.platforms.values():
        subcategories.append(section[config.platforms.key_category])
    return subcategories

# Get all platforms
def GetAllPlatforms():
    platforms = []
    for key in config.platforms.keys():
        platforms.append(key)
    return platforms

# Determine if platform is valid
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

# Get transform types
def GetTransformTypes(platform_name):
    return GetPlatformValue(platform_name, config.platforms.key_transforms)

# Get addons types
def GetAddonTypes(platform_name):
    return GetPlatformValue(platform_name, config.platforms.key_addons)

# Get launcher types
def GetLauncherTypes(platform_names):
    return GetPlatformValue(platform_name, config.platforms.key_launcher)

# Determine if platform has transform type
def HasTransformType(platform_name, transform_type):
    return transform_type in GetTransformTypes(platform_name)

# Check if updates are possible
def AreUpdatesPossible(platform_name):
    return config.platforms.addon_type_updates in GetTransformTypes(platform_name)

# Check if dlc are possible
def AreDLCPossible(platform_name):
    return config.platforms.addon_type_dlc in GetTransformTypes(platform_name)

# Check if addons are possible
def AreAddonsPossible(platform_name):
    return len(GetAddonTypes(platform_name)) == 0
