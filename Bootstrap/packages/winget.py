# Imports
import os
import sys

# Local imports
import constants
import util

###########################################################
# WinGet
###########################################################
winget = {}
winget[constants.EnvironmentType.LOCAL_UBUNTU] = []
winget[constants.EnvironmentType.LOCAL_WINDOWS] = []
winget[constants.EnvironmentType.REMOTE_UBUNTU] = []
winget[constants.EnvironmentType.REMOTE_WINDOWS] = []

###########################################################
# WinGet - Local Windows
###########################################################
winget[constants.EnvironmentType.LOCAL_WINDOWS] += [

    # Devel
    "MHNexus.HxD",
    "Microsoft.DotNet.SDK.8",
    "Microsoft.NuGet",
    "Microsoft.VisualStudio.2022.Community",

    # Drivers
    "CodecGuide.K-LiteCodecPack.Mega",
    "Nvidia.GeForceExperience",

    # Games
    "Valve.Steam",
    "Valve.SteamCMD",

    # Graphics
    "GIMP.GIMP",
    "VideoLAN.VLC",

    # Libs
    "Microsoft.EdgeWebView2Runtime",

    # Net
    "subhra74.XtremeDownloadManager",

    # Perl
    "StrawberryPerl.StrawberryPerl",

    # Python
    "Python.Python.3.11",

    # Sandbox
    "Sandboxie.Plus",

    # Sound
    "QmmpDevelopmentTeam.qmmp",

    # Text
    "Notepad++.Notepad++",
    "VSCodium.VSCodium",

    # Utils
    "chrisant996.Clink",
    "Cryptomator.Cryptomator",
    "Cygwin.Cygwin",
    "GeekUninstaller.GeekUninstaller",
    "LIGHTNINGUK.ImgBurn",
    "Maximus5.ConEmu",
    "mcmilk.7zip-zstd",
    "WinDirStat.WinDirStat",

    # VCS
    "Git.Git",
    "TortoiseGit.TortoiseGit",

    # Web
    "Discord.Discord",
    "Mozilla.Firefox",
    "OpenWhisperSystems.Signal",
    "Telegram.TelegramDesktop",
    "StefansTools.grepWin"
]
