# Imports
from . import appimagetool
from . import cdecrypt
from . import curl
from . import dxvk
from . import exiftool
from . import extractxiso
from . import ffmpeg
from . import firefox
from . import geckodriver
from . import git
from . import hactool
from . import jdupes
from . import mkpl
from . import lgogdownloader
from . import ludusavi
from . import mametools
from . import ndecrypt
from . import nircmd
from . import pegasus
from . import projectctr
from . import ps3dec
from . import psngetpkginfo
from . import psvstrip
from . import psvtools
from . import pylnk
from . import python
from . import rclone
from . import sandboxie
from . import sevenzip
from . import sunshine
from . import threedsromtool
from . import vkd3d
from . import wad2bin
from . import wine
from . import xcitrimmer
from . import xorriso

# Tool instances
instances = [
    appimagetool.AppImageTool(),
    cdecrypt.CDecrypt(),
    curl.Curl(),
    dxvk.DXVK(),
    exiftool.ExifTool(),
    extractxiso.ExtractXIso(),
    ffmpeg.FFMpeg(),
    firefox.Firefox(),
    geckodriver.GeckoDriver(),
    git.Git(),
    hactool.HacTool(),
    jdupes.Jdupes(),
    mkpl.Mkpl(),
    lgogdownloader.LGOGDownloader(),
    ludusavi.Ludusavi(),
    mametools.MameTools(),
    ndecrypt.NDecrypt(),
    nircmd.NirCmd(),
    pegasus.Pegasus(),
    projectctr.ProjectCTR(),
    ps3dec.PS3Dec(),
    psngetpkginfo.PSNGetPkgInfo(),
    psvstrip.PSVStrip(),
    psvtools.PSVTools(),
    pylnk.PyLnk(),
    python.Python(),
    rclone.RClone(),
    sandboxie.Sandboxie(),
    sevenzip.SevenZip(),
    sunshine.Sunshine(),
    threedsromtool.ThreeDSRomTool(),
    vkd3d.VKD3D(),
    wad2bin.Wad2Bin(),
    wine.Wine(),
    xcitrimmer.XCITrimmer(),
    xorriso.XorrISO()
]

# Get tools
def GetTools():
    return instances
