# Imports
import os
import sys

# Local imports
import environment

###########################################################
# Python packages
###########################################################
python_packages = [
    "pip",
    "wheel",
    "psutil",
    "selenium",
    "requests",
    "pathlib",
    "PySimpleGUI",
    "Pillow",
    "bs4",
    "lxml",
    "mergedeep",
    "fuzzywuzzy",
    "dictdiffer",
    "termcolor",
    "pycryptodome",
    "pycryptodomex",
    "cryptography",
    "aenum",
    "fastxor",
    "packaging",
    "ecdsa",
    "schedule",
    "python-dateutil",
    "xxhash",
    "screeninfo",
    "tqdm"
]
if environment.IsWindowsPlatform():
    python_packages += [
        "pywin32",
        "pyuac"
    ]
