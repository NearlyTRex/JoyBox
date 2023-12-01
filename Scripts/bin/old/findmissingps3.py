import os, os.path
import sys
import hashlib
import shutil
import pathlib
import subprocess
import zipfile

def IsRapFileRequired(pkg_filename):
    cmd = ["python3", "PSN_get_pkg_info.py", pkg_filename]
    output = subprocess.check_output(cmd).decode('UTF-8')
    return ("DRM Type:     3" not in output)

missing_content_ids = []
startdir = os.getcwd()
for root, dirs, files in os.walk(".", topdown=False):
    for name in files:
        basename = pathlib.Path(name).stem
        if "." in basename:
            basename = basename.split(".")[0]
        pkgfilename = os.path.realpath(os.path.join(root, basename + ".pkg"))
        rapfilename = os.path.realpath(os.path.join(root, basename + ".rap"))
        content_id_path = str(pathlib.Path(pkgfilename).parent.name)
        content_id_entry = content_id_path + "\t" + basename
        if name.lower().endswith(".pkg"):
            if not os.path.exists(rapfilename):
                if IsRapFileRequired(pkgfilename):
                    missing_content_ids.append(content_id_entry)
        elif name.lower().endswith(".rap"):
            if not os.path.exists(pkgfilename):
                missing_content_ids.append(content_id_entry)

missing_content_ids.sort()
for content_id in missing_content_ids:
    print(content_id)
