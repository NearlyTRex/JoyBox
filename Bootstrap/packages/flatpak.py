# Imports
import os
import sys

# Local imports
import constants
import util

###########################################################
# Flatpak
###########################################################
flatpak = {}
flatpak[constants.LOCAL_UBUNTU] = []
flatpak[constants.LOCAL_WINDOWS] = []
flatpak[constants.REMOTE_UBUNTU] = []
flatpak[constants.REMOTE_WINDOWS] = []

###########################################################
# Flatpak - Local Ubuntu
###########################################################
flatpak[constants.LOCAL_UBUNTU] += [

    # Devel
    ["flathub", "com.axosoft.GitKraken"],
    ["flathub", "com.jetbrains.IntelliJ-IDEA-Community"],
    ["flathub", "org.mapeditor.Tiled"],

    # Text
    ["flathub", "com.vscodium.codium"],

    # Utils
    ["flathub", "org.cryptomator.Cryptomator"],

    # Web
    ["flathub", "com.discordapp.Discord"],
    ["flathub", "org.signal.Signal"],
    ["flathub", "org.telegram.desktop"]
]
