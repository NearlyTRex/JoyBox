import os, os.path
import sys
import subprocess
from pathlib import Path

startdir = os.getcwd()
for root, dirs, files in os.walk(startdir):
    for file in files:
        if file.endswith((".key")):
            gamefile = os.path.realpath(os.path.join(root, file))
            gamedir = os.path.dirname(gamefile)
            gamepath = Path(gamefile)
            gamebasename = gamepath.stem
            gamesuffix = gamepath.suffix
            os.chdir(gamedir)
            cmd = "xxd -p \"%s\" > \"%s\"" % (gamebasename + gamesuffix, gamebasename + ".key.txt")
            print(cmd)
            subprocess.check_call(cmd, shell=True)
            os.chdir(startdir)
