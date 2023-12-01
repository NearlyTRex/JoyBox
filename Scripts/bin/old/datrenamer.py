import os, os.path
import hashlib
import shutil

def getFileMD5Checksum(filename):
    md5_hash = hashlib.md5()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5_hash.update(chunk)
    return md5_hash.hexdigest().upper()

def getFileSHA256Checksum(filename):
    sha256_hash = hashlib.sha256()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest().upper()

def readDatabase(filename):
    database = {}
    f = open(filename, "r", encoding='utf-8', errors='ignore')
    while True:
        line = f.readline().strip()
        if not line:
            break
        tokens = line.split(" || ")
        entry = {}
        entry["name"] = tokens[0]
        entry["file"] = tokens[1].lower()
        entry["ext"] = os.path.splitext(tokens[1])[1].lower()
        entry["md5"] = tokens[2].lower()
        entry["sha256"] = tokens[3].lower()
        database[entry["md5"]] = entry
    f.close()
    return database

db = readDatabase("datfile.txt")
for root, dirs, files in os.walk(".", topdown=False):
    for name in files:
        print("Examining %s" % name)
        index = getFileMD5Checksum(os.path.join(root, name)).lower()
        if index in db:
            print("Found match")
            entry = db[index]
            entry_name = entry["name"]
            entry_ext = entry["ext"]
            oldpath = os.path.join(root, name)
            newpath = os.path.join(root, entry_name + entry_ext)
            if oldpath != newpath:
                print(oldpath, newpath)
                os.rename(oldpath, newpath)
