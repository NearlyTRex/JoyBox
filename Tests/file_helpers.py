# Imports
import os


###########################################################
# Files on disk
#
# Shared by the suites that build a directory on disk and compare what ends
# up in it.
###########################################################

def write(path, contents = "x"):
    os.makedirs(os.path.dirname(str(path)), exist_ok = True)
    with open(path, "w", encoding = "utf-8") as f:
        f.write(contents)
    return str(path)


# Every file under root, relative and sorted, so a layout can be compared
# as a whole rather than one exists() call at a time
def tree(root):
    found = []
    for directory, _, filenames in os.walk(str(root)):
        for filename in filenames:
            found.append(os.path.relpath(os.path.join(directory, filename), str(root)))
    return sorted(found)
