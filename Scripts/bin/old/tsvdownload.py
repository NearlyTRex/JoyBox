import os, os.path
import shutil
import wget
import pathlib

idx_region = 1
idx_link = 3
startdir = os.getcwd()
for root, dirs, files in os.walk(".", topdown=False):
    for name in files:
        if name.lower().endswith(".tsv"):
            basename = pathlib.Path(name).stem
            tsvfilename = os.path.realpath(os.path.join(root, name))
            with open(tsvfilename, "r", encoding="utf-8", errors="ignore") as f:
                tsvfilelines = f.readlines()
                for i in range(0, len(tsvfilelines)):
                    line = tsvfilelines[i].strip()
                    tokens = line.split("\t")
                    if len(tokens) >= 4:
                        token_region = tokens[idx_region]
                        token_link = tokens[idx_link]
                        if token_region == "US" and token_link.startswith("http"):
                            folder = os.path.realpath(".")
                            file = os.path.join(folder, wget.filename_from_url(token_link))
                            if os.path.exists(file):
                                print("Skipping download of %s" % file)
                                continue
                            print("Downloading %s to %s ... (%s/%s)" % (token_link, folder, i + 1, len(tsvfilelines)))
                            wget.download(token_link, out = folder)
                            print("\n")
