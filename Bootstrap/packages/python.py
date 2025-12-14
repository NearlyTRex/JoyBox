# Imports
import os
import sys

# Local imports
import constants
import util

###########################################################
# Python
###########################################################
python = {}
python[constants.EnvironmentType.LOCAL_UBUNTU] = []
python[constants.EnvironmentType.LOCAL_WINDOWS] = []
python[constants.EnvironmentType.REMOTE_UBUNTU] = []
python[constants.EnvironmentType.REMOTE_WINDOWS] = []

###########################################################
# Python - Local Ubuntu
###########################################################
python[constants.EnvironmentType.LOCAL_UBUNTU] += [
    "aenum",
    "anthropic",
    "bs4",
    "colorama",
    "cryptography",
    "dictdiffer",
    "ecdsa",
    "fastxor",
    "GitPython",
    "html-text",
    "InquirerPy",
    "json5",
    "keyring",
    "lxml",
    "mergedeep",
    "mutagen",
    "packaging",
    "pathlib",
    "Pillow",
    "pip",
    "platformdirs",
    "protobuf",
    "psutil",
    "pycryptodome",
    "pycryptodomex",
    "pyghidra",
    "PyGithub",
    "python-dateutil",
    "python-Levenshtein",
    "python-magic",
    "pyxdg",
    "requests",
    "rich",
    "ruamel.yaml",
    "schedule",
    "screeninfo",
    "selenium",
    "termcolor",
    "thefuzz",
    "tqdm",
    "typer",
    "Unidecode",
    "vdf",
    "webdriver_manager",
    "wheel",
    "xmltodict",
    "xxhash"
]

###########################################################
# Python - Local Windows
###########################################################
python[constants.EnvironmentType.LOCAL_WINDOWS] += python[constants.EnvironmentType.LOCAL_UBUNTU]
python[constants.EnvironmentType.LOCAL_WINDOWS] += [
    "pywin32",
    "pyuac"
]
