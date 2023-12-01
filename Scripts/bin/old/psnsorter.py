import os, os.path
import hashlib
import shutil
import pathlib
import subprocess
import zipfile

psn_exts = [
    ".pkg",
    ".rap",
    ".work.bin",
    ".fake.rif"
]

def splitext(path):
    if len(path.split('.')) > 2:
        return path.split('.')[0],'.'.join(path.split('.')[-2:])
    return os.path.splitext(path)

startdir = os.getcwd()
for root, dirs, files in os.walk(".", topdown=False):
    for name in files:
        for psn_ext in psn_exts:
            if name.lower().endswith(psn_ext):
                basename, ext = splitext(name)
                oldfilename = os.path.realpath(os.path.join(root, name))
                if len(basename) == 36:
                    basename_tokens = basename.split("-")
                    gameid_tokens = basename_tokens[1].split("_")
                    gameid = gameid_tokens[0]
                    newfolder = os.path.realpath(os.path.join(root, gameid))
                    newfilename = os.path.join(newfolder, basename + psn_ext)
                    os.makedirs(newfolder, exist_ok = True)
                    os.rename(oldfilename, newfilename)
                    print(oldfilename, newfilename)
