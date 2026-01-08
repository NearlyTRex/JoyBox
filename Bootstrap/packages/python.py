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
    "audible",
    "audible-cli",
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
    "pikepdf",
    "Pillow",
    "pip",
    "pipenv",
    "platformdirs",
    "protobuf",
    "psutil",
    "pycryptodome",
    "pycryptodomex",
    "pyghidra",
    "PyGithub",
    "PyQt5",
    "python-dateutil",
    "python-Levenshtein",
    "python-magic",
    "pyxdg",
    "questionary",
    "requests",
    "rich",
    "ruamel.yaml",
    "schedule",
    "screeninfo",
    "selenium",
    "tabulate",
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
