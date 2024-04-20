# Imports
import os
import sys
import subprocess

###########################################################
# Info
###########################################################

# Check for windows
def IsWindowsPlatform():
    return sys.platform.startswith("win32")

# Check for linux
def IsLinuxPlatform():
    return sys.platform.startswith("linux")

###########################################################
# Path
###########################################################

# Add to windows path
def AddToWindowsPath(path):
    subprocess.check_call("setx PATH \"%%PATH%%;%s\"" % path, shell = True)

# Add to linux path
def AddToLinuxPath(path):
    subprocess.check_call("echo 'export PATH=\"%s:$PATH\"' >> ~/.bashrc" % path, shell = True)

# Add to path
def AddToPath(path):
    if IsWindowsPlatform():
        AddToWindowsPath(path)
    elif IsLinuxPlatform():
        AddToLinuxPath(path)

###########################################################
# Distro
###########################################################

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

# Get linux distro id
def GetLinuxDistroId():
    return GetLinuxDistroValue("ID")

# Get linux distro id like
def GetLinuxDistroIdLike():
    return GetLinuxDistroValue("ID_LIKE")

# Get ubuntu codename
def GetUbuntuCodename():
    return GetLinuxDistroValue("UBUNTU_CODENAME")

# Check for ubuntu distro
def IsUbuntuDistro():
    if "ubuntu" in GetLinuxDistroName().lower():
        return True
    elif "ubuntu" in GetLinuxDistroId():
        return True
    elif "ubuntu" in GetLinuxDistroIdLike():
        return True
    return False

# Check for ubuntu mantic distro
def IsUbuntuMantic():
    if "mantic" in GetUbuntuCodename():
        return True
    if "23.10" in environment.GetLinuxDistroVersion():
        return True
    return False

# Check for ubuntu lunar distro
def IsUbuntuLunar():
    if "lunar" in GetUbuntuCodename():
        return True
    if "23.04" in environment.GetLinuxDistroVersion():
        return True
    return False

# Check for ubuntu jammy distro
def IsUbuntuJammy():
    if "jammy" in GetUbuntuCodename():
        return True
    if "22.04" in environment.GetLinuxDistroVersion():
        return True
    return False

# Check for ubuntu focal distro
def IsUbuntuFocal():
    if "focal" in GetUbuntuCodename():
        return True
    if "20.04" in environment.GetLinuxDistroVersion():
        return True
    return False
