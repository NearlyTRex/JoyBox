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
flatpak[constants.EnvironmentType.LOCAL_UBUNTU] = []
flatpak[constants.EnvironmentType.LOCAL_WINDOWS] = []
flatpak[constants.EnvironmentType.REMOTE_UBUNTU] = []
flatpak[constants.EnvironmentType.REMOTE_WINDOWS] = []

###########################################################
# Flatpak - Local Ubuntu
###########################################################
flatpak[constants.EnvironmentType.LOCAL_UBUNTU] += [

    # Admin
    {"repository": "flathub", "name": "com.github.tchx84.Flatseal"},

    # Devel
    {"repository": "flathub", "name": "com.axosoft.GitKraken"},
    {"repository": "flathub", "name": "com.jetbrains.IntelliJ-IDEA-Community"},
    {"repository": "flathub", "name": "org.mapeditor.Tiled"},

    # Games
    {"repository": "flathub", "name": "com.heroicgameslauncher.hgl"},

    # Text
    {"repository": "flathub", "name": "com.vscodium.codium"},

    # Utils
    {"repository": "flathub", "name": "org.cryptomator.Cryptomator"},

    # Web
    {"repository": "flathub", "name": "com.discordapp.Discord"},
    {"repository": "flathub", "name": "org.signal.Signal"},
    {"repository": "flathub", "name": "org.telegram.desktop"},
]
