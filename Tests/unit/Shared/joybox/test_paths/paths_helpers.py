# Imports
import os


def write(path, contents = "x"):
    os.makedirs(os.path.dirname(str(path)), exist_ok = True)
    with open(path, "w", encoding = "utf-8") as f:
        f.write(contents)
    return str(path)
