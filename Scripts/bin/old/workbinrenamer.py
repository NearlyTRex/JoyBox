import os, os.path
import hashlib
import shutil
import pathlib
import subprocess
import zipfile

startdir = os.getcwd()
for root, dirs, files in os.walk(".", topdown=False):
    for name in files:
        if name.lower().endswith(".rif") or (name.lower().startswith("work") and name.lower().endswith(".bin")):
            basename = pathlib.Path(name).stem
            oldfilename = os.path.realpath(os.path.join(root, name))
            with open(oldfilename, 'rb') as pkgfile:
                pkgfile.seek(0x10)
                contentid = pkgfile.read(0x24).decode("utf-8")
                newfilename = os.path.realpath(os.path.join(root, contentid + ".work.bin"))
                if oldfilename != newfilename:
                    os.rename(oldfilename, newfilename)
