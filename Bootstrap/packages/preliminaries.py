# Imports
import os
import sys

# Local imports
import constants
import util

###########################################################
# Preliminaries
###########################################################
preliminaries = {}
preliminaries[constants.LOCAL_UBUNTU] = []
preliminaries[constants.LOCAL_WINDOWS] = []
preliminaries[constants.REMOTE_UBUNTU] = []
preliminaries[constants.REMOTE_WINDOWS] = []

###########################################################
# Preliminaries - Local Ubuntu
###########################################################

# Wine
if not os.path.isfile("/usr/bin/wine"):

    # Setup architecture
    preliminaries[constants.LOCAL_UBUNTU] += [
        "sudo dpkg --add-architecture i386"
    ]

    # Setup key
    preliminaries[constants.LOCAL_UBUNTU] += [
        "sudo mkdir -pm755 /etc/apt/keyrings",
        "sudo wget -O /etc/apt/keyrings/winehq-archive.key https://dl.winehq.org/wine-builds/winehq.key"
    ]

    # Setup sources
    preliminaries[constants.LOCAL_UBUNTU] += [
        "sudo wget -NP /etc/apt/sources.list.d/ https://dl.winehq.org/wine-builds/ubuntu/dists/%s/winehq-%s.sources" % (
            util.GetUbuntuCodename(),
            util.GetUbuntuCodename()
        )
    ]

# Brave
if not os.path.isfile("/usr/bin/brave-browser"):

    # Setup key
    preliminaries[constants.LOCAL_UBUNTU] += [
        "sudo curl -fsSLo /usr/share/keyrings/brave-browser-archive-keyring.gpg https://brave-browser-apt-release.s3.brave.com/brave-browser-archive-keyring.gpg"
    ]

    # Setup sources
    preliminaries[constants.LOCAL_UBUNTU] += [
        "echo 'deb [signed-by=/usr/share/keyrings/brave-browser-archive-keyring.gpg] https://brave-browser-apt-release.s3.brave.com/ stable main' | sudo tee /etc/apt/sources.list.d/brave-browser-release.list"
    ]

# Chrome
if not os.path.isfile("/usr/bin/google-chrome"):

    # Install deb
    preliminaries[constants.LOCAL_UBUNTU] += [
        "wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb",
        "sudo dpkg -i google-chrome-stable_current_amd64.deb"
    ]

# 1Password
if not os.path.isfile("/usr/bin/1password"):

    # Setup key
    preliminaries[constants.LOCAL_UBUNTU] += [
        "curl -sS https://downloads.1password.com/linux/keys/1password.asc | sudo gpg --dearmor --output /usr/share/keyrings/1password-archive-keyring.gpg"
    ]

    # Setup sources
    preliminaries[constants.LOCAL_UBUNTU] += [
        "echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/1password-archive-keyring.gpg] https://downloads.1password.com/linux/debian/amd64 stable main' | sudo tee /etc/apt/sources.list.d/1password.list"
    ]

    # Setup policy
    preliminaries[constants.LOCAL_UBUNTU] += [
        "sudo mkdir -p /etc/debsig/policies/AC2D62742012EA22/",
        "curl -sS https://downloads.1password.com/linux/debian/debsig/1password.pol | sudo tee /etc/debsig/policies/AC2D62742012EA22/1password.pol",
        "sudo mkdir -p /usr/share/debsig/keyrings/AC2D62742012EA22",
        "curl -sS https://downloads.1password.com/linux/keys/1password.asc | sudo gpg --dearmor --output /usr/share/debsig/keyrings/AC2D62742012EA22/debsig.gpg"
    ]
