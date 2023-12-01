import os, os.path
import shutil
import subprocess
import pathlib
import time

sleep_time = 2

#PS3 = Title ID || Region || Name || PKG direct link || RAP || Content ID || Last Modification Date || Download .RAP file || File Size || SHA256

idx_titleid = 0
idx_region = 1
idx_name = 2
idx_link = 3
idx_rap = 4
idx_contentid = 5
idx_lastmod = 6
idx_downrap = 7
idx_filesize = 8
idx_sha256 = 9

startdir = os.getcwd()
for root, dirs, files in os.walk(".", topdown=False):
    for name in files:
        if name.lower().endswith(".tsv"):
            basename = pathlib.Path(name).stem
            tsvfilename = os.path.realpath(os.path.join(root, name))
            with open(tsvfilename, "r", encoding='utf-8', errors='ignore') as f:
                while True:
                    line = f.readline().strip()
                    if not line:
                        break
                    tokens = line.split("\t")
                    if len(tokens) >= 7:
                        token_contentid = tokens[idx_contentid]
                        token_rap = tokens[idx_rap]
                        token_region = tokens[idx_region]
                        token_name = tokens[idx_name]
                        if " " in token_contentid:
                            continue
                        if len(token_rap) == 0:
                            continue
                        if token_region != "US":
                            continue
                        if "unlock key" in token_name.lower():
                            continue
                        if "missing" in token_rap.lower():
                            continue
                        basename = token_contentid + ".rap"
                        folder = os.path.realpath(".")
                        file = os.path.join(folder, basename)
                        if os.path.exists(file):
                            print("Skipping download of %s" % file)
                            continue
                        print("Downloading %s to %s ..." % (basename, folder))
                        cmd = ["wget", "-O", basename, "https://nopaystation.com/tools/rap2file/%s/%s" % (token_contentid, token_rap)]
                        subprocess.check_call(cmd)
                        print("Sleeping...")
                        time.sleep(sleep_time)
