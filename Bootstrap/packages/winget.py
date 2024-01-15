# Imports
import os
import sys
import subprocess

# Local imports
import environment

###########################################################
# Preliminaries
###########################################################
preliminaries = []

###########################################################
# Packages
###########################################################
packages = [

    # Devel
    "MHNexus.HxD",
    "Microsoft.VisualStudio.2022.Community",

    # Drivers
    "CodecGuide.K-LiteCodecPack.Mega",
    "Nvidia.GeForceExperience",

    # Graphics
    "GIMP.GIMP",
    "VideoLAN.VLC",

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

###########################################################
# Functions
###########################################################

# Setup
def Setup(ini_values = {}):

    # Get winget tools
    winget_exe = ini_values["Tools.WinGet"]["winget_exe"]
    winget_install_dir = os.path.expandvars(ini_values["Tools.WinGet"]["winget_install_dir"])
    winget_tool = os.path.join(winget_install_dir, winget_exe)

    # Run preliminaries
    for preliminary in preliminaries:
        subprocess.run(preliminary, shell=True)

    # Install packages
    for package in packages:
        subprocess.run([winget_tool, "install", "-e", "--id", package])
