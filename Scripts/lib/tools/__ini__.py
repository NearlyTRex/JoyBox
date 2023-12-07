# Imports
import appimagetool
import cdecrypt
import exiftool
import extractxiso
import ffmpeg
import geckodriver
import hactool
import ludusavi
import mametools
import ndecrypt
import nircmd
import pegasus
import projectctr
import ps3dec
import psvstrip
import rclone
import sevenzip
import sunshine
import threedsromtool
import wad2bin
import xcicutter

# Get tools
def GetTools():
    return [
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
        sunshine.Sunshin(),
        threedsromtool.ThreeDSRomTool(),
        wad2bin.Wad2Bin(),
        xcicutter.XCICutter()
    ]
