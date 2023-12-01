import os, os.path
import hashlib
import shutil
import pathlib
import subprocess
import zipfile

missing_content_ids = []
startdir = os.getcwd()
for root, dirs, files in os.walk(".", topdown=False):
    for name in files:
        basename = pathlib.Path(name).stem
        if "." in basename:
            basename = basename.split(".")[0]
        pkgfilename = os.path.realpath(os.path.join(root, basename + ".pkg"))
        workbinfilename = os.path.realpath(os.path.join(root, basename + ".work.bin"))
        content_id_path = str(pathlib.Path(pkgfilename).parent.name)
        content_id_entry = content_id_path + "\t" + basename
        if name.lower().endswith(".pkg"):
            if not os.path.exists(workbinfilename):
                missing_content_ids.append(content_id_entry)
        elif name.lower().endswith(".work.bin"):
            if not os.path.exists(pkgfilename):
                missing_content_ids.append(content_id_entry)

missing_content_ids.sort()
for content_id in missing_content_ids:
    print(content_id)
