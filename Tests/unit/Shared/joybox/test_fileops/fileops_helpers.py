# Imports
import os
import stat


def write(path, contents = "x"):
    os.makedirs(os.path.dirname(str(path)), exist_ok = True)
    with open(path, "w", encoding = "utf-8") as f:
        f.write(contents)
    return str(path)


def read(path):
    with open(path, "r", encoding = "utf-8") as f:
        return f.read()


def tree(root):
    found = set()
    for base, dirs, files in os.walk(root):
        for name in dirs + files:
            found.add(os.path.relpath(os.path.join(base, name), root))
    return found


def fail(*args, **kwargs):
    raise OSError("simulated failure")


def mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def make_source(root):
    write(root / "a.txt", "a")
    write(root / "sub" / "b.txt", "b")
    return str(root)
