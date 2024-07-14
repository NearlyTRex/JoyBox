# Imports
from . import appimagetool
from . import balenaetcher
from . import cdecrypt
from . import curl
from . import dxvk
from . import exiftool
from . import extractxiso
from . import ffmpeg
from . import firefox
from . import geckodriver
from . import git
from . import goldbergemu
from . import gpg
from . import hactool
from . import jdupes
from . import mkpl
from . import lgogdownloader
from . import ludusavi
from . import ludusavimanifest
from . import mametools
from . import moonlight
from . import ndecrypt
from . import nile
from . import nircmd
from . import pegasus
from . import perl
from . import projectctr
from . import ps3dec
from . import psngetpkginfo
from . import psvstrip
from . import psvtools
from . import pylnk
from . import pysimplegui
from . import python
from . import rclone
from . import sandboxie
from . import sevenzip
from . import sigtop
from . import steamcmd
from . import steamdepotdownloader
from . import steamless
from . import sunshine
from . import tar
from . import threedsromtool
from . import vkd3d
from . import wad2bin
from . import wine
from . import xcitrimmer
from . import xorriso
from . import ytdlp

# Tool instances
instances = [
    appimagetool.AppImageTool(),
    balenaetcher.BalenaEtcher(),
    cdecrypt.CDecrypt(),
    curl.Curl(),
    dxvk.DXVK(),
    exiftool.ExifTool(),
    extractxiso.ExtractXIso(),
    ffmpeg.FFMpeg(),
    firefox.Firefox(),
    geckodriver.GeckoDriver(),
    git.Git(),
    goldbergemu.GoldbergEmu(),
    gpg.Gpg(),
    hactool.HacTool(),
    jdupes.JDupes(),
    mkpl.Mkpl(),
    lgogdownloader.LGOGDownloader(),
    ludusavi.Ludusavi(),
    ludusavimanifest.LudusaviManifest(),
    mametools.MameTools(),
    moonlight.Moonlight(),
    ndecrypt.NDecrypt(),
    nircmd.NirCmd(),
    nile.Nile(),
    pegasus.Pegasus(),
    perl.Perl(),
    projectctr.ProjectCTR(),
    ps3dec.PS3Dec(),
    psngetpkginfo.PSNGetPkgInfo(),
    psvstrip.PSVStrip(),
    psvtools.PSVTools(),
    pylnk.PyLnk(),
    pysimplegui.PySimpleGUI(),
    python.Python(),
    rclone.RClone(),
    sandboxie.Sandboxie(),
    sevenzip.SevenZip(),
    sigtop.Sigtop(),
    steamcmd.SteamCMD(),
    steamdepotdownloader.SteamDepotDownloader(),
    steamless.Steamless(),
    sunshine.Sunshine(),
    tar.Tar(),
    threedsromtool.ThreeDSRomTool(),
    vkd3d.VKD3D(),
    wad2bin.Wad2Bin(),
    wine.Wine(),
    xcitrimmer.XCITrimmer(),
    xorriso.XorrISO(),
    ytdlp.YtDlp()
]

# Get tools
def GetTools():
    return instances
