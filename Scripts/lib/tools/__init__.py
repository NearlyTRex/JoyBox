# Imports
from . import appimagetool
from . import cdecrypt
from . import exiftool
from . import extractxiso
from . import ffmpeg
from . import geckodriver
from . import hactool
from . import ludusavi
from . import mametools
from . import ndecrypt
from . import nircmd
from . import pegasus
from . import projectctr
from . import ps3dec
from . import psvstrip
from . import rclone
from . import sevenzip
from . import sunshine
from . import threedsromtool
from . import wad2bin
from . import xcicutter

# Tool instances
instances = [
    appimagetool.AppImageTool(),
    cdecrypt.CDecrypt(),
    exiftool.ExifTool(),
    extractxiso.ExtractXIso(),
    ffmpeg.FFMpeg(),
    geckodriver.GeckoDriver(),
    hactool.HacTool(),
    ludusavi.Ludusavi(),
    mametools.MameTools(),
    ndecrypt.NDecrypt(),
    nircmd.NirCmd(),
    pegasus.Pegasus(),
    projectctr.ProjectCTR(),
    ps3dec.PS3Dec(),
    psvstrip.PSVStrip(),
    rclone.RClone(),
    sevenzip.SevenZip(),
    sunshine.Sunshine(),
    threedsromtool.ThreeDSRomTool(),
    wad2bin.Wad2Bin(),
    xcicutter.XCICutter()
]

# Get tools
def GetTools():
    return instances
