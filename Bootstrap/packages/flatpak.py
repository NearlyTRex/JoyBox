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
    {"id": "com.github.tchx84.Flatseal", "name": "Flatseal", "description": "Manage Flatpak permissions", "category": "Admin"},

    # Devel
    {"id": "com.jetbrains.IntelliJ-IDEA-Community", "name": "IntelliJ IDEA", "description": "Java IDE", "category": "Devel"},
    {"id": "org.mapeditor.Tiled", "name": "Tiled", "description": "2D map editor for games", "category": "Devel"},

    # Games
    {"id": "com.heroicgameslauncher.hgl", "name": "Heroic Games Launcher", "description": "Epic/GOG/Amazon game launcher", "category": "Games"},

    # Utils
    {"id": "org.cryptomator.Cryptomator", "name": "Cryptomator", "description": "Cloud storage encryption", "category": "Utils"},

    # Web
    {"id": "com.discordapp.Discord", "name": "Discord", "description": "Voice and text chat", "category": "Web"},
    {"id": "org.signal.Signal", "name": "Signal", "description": "Private messenger", "category": "Web"},
    {"id": "org.telegram.desktop", "name": "Telegram", "description": "Cloud-based messenger", "category": "Web"},
]
