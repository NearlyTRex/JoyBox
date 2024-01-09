# Imports
import os
import sys

# Check for windows
def IsWindowsPlatform():
    return sys.platform.startswith("win32")

# Check for linux
def IsLinuxPlatform():
    return sys.platform.startswith("linux")

# Get linux distro value
def GetLinuxDistroValue(field):
    if os.path.isfile("/etc/os-release"):
        with open("/etc/os-release", "r", encoding="utf-8") as f:
            for line in f.readlines():
                if line.startswith("#"):
                    continue
                tokens = line.strip().split("=")
                if len(tokens) == 2:
                    if tokens[0] == field:
                        return tokens[1].strip("\"")
    return ""

# Get linux distro name
def GetLinuxDistroName():
    return GetLinuxDistroValue("NAME")

# Get linux distro version
def GetLinuxDistroVersion():
    return GetLinuxDistroValue("VERSION")
