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

    # API/Services
    {"id": "anthropic", "name": "Anthropic", "description": "Claude AI API client", "category": "API"},
    {"id": "PyGithub", "name": "PyGithub", "description": "GitHub API wrapper", "category": "API"},
    {"id": "requests", "name": "Requests", "description": "HTTP library", "category": "API"},

    # Audio
    {"id": "audible", "name": "Audible", "description": "Audible API library", "category": "Audio"},
    {"id": "audible-cli", "name": "Audible CLI", "description": "Audible command line tool", "category": "Audio"},
    {"id": "mutagen", "name": "Mutagen", "description": "Audio metadata handler", "category": "Audio"},

    # CLI
    {"id": "colorama", "name": "Colorama", "description": "Cross-platform colored terminal text", "category": "CLI"},
    {"id": "InquirerPy", "name": "InquirerPy", "description": "Interactive command line prompts", "category": "CLI"},
    {"id": "questionary", "name": "Questionary", "description": "CLI prompts and dialogs", "category": "CLI"},
    {"id": "rich", "name": "Rich", "description": "Rich text and formatting in terminal", "category": "CLI"},
    {"id": "tabulate", "name": "Tabulate", "description": "Pretty-print tabular data", "category": "CLI"},
    {"id": "termcolor", "name": "Termcolor", "description": "ANSI color formatting", "category": "CLI"},
    {"id": "tqdm", "name": "tqdm", "description": "Progress bar", "category": "CLI"},
    {"id": "typer", "name": "Typer", "description": "CLI application framework", "category": "CLI"},

    # Crypto
    {"id": "cryptography", "name": "Cryptography", "description": "Cryptographic recipes and primitives", "category": "Crypto"},
    {"id": "ecdsa", "name": "ECDSA", "description": "Elliptic curve cryptography", "category": "Crypto"},
    {"id": "pycryptodome", "name": "PyCryptodome", "description": "Cryptographic library", "category": "Crypto"},
    {"id": "pycryptodomex", "name": "PyCryptodomex", "description": "Cryptographic library (standalone)", "category": "Crypto"},

    # Data
    {"id": "dictdiffer", "name": "Dictdiffer", "description": "Dictionary difference calculator", "category": "Data"},
    {"id": "json5", "name": "JSON5", "description": "JSON5 parser/serializer", "category": "Data"},
    {"id": "mergedeep", "name": "Mergedeep", "description": "Deep merge dictionaries", "category": "Data"},
    {"id": "protobuf", "name": "Protobuf", "description": "Protocol buffers", "category": "Data"},
    {"id": "ruamel.yaml", "name": "Ruamel.YAML", "description": "YAML parser with round-trip support", "category": "Data"},
    {"id": "vdf", "name": "VDF", "description": "Valve Data Format parser", "category": "Data"},
    {"id": "xmltodict", "name": "XMLtoDict", "description": "XML to dict converter", "category": "Data"},

    # Dev
    {"id": "GitPython", "name": "GitPython", "description": "Git repository interface", "category": "Dev"},
    {"id": "pip", "name": "pip", "description": "Python package installer", "category": "Dev"},
    {"id": "pipenv", "name": "Pipenv", "description": "Python dev workflow tool", "category": "Dev"},
    {"id": "pyghidra", "name": "PyGhidra", "description": "Ghidra Python bindings", "category": "Dev"},
    {"id": "wheel", "name": "Wheel", "description": "Python wheel packaging", "category": "Dev"},

    # Graphics
    {"id": "Pillow", "name": "Pillow", "description": "Image processing library", "category": "Graphics"},

    # GUI
    {"id": "PyQt5", "name": "PyQt5", "description": "Qt5 bindings for Python", "category": "GUI"},
    {"id": "screeninfo", "name": "Screeninfo", "description": "Screen/monitor information", "category": "GUI"},

    # Parsing
    {"id": "bs4", "name": "BeautifulSoup", "description": "HTML/XML parser", "category": "Parsing"},
    {"id": "html-text", "name": "HTML-Text", "description": "Extract text from HTML", "category": "Parsing"},
    {"id": "lxml", "name": "lxml", "description": "XML/HTML processing library", "category": "Parsing"},

    # PDF
    {"id": "pikepdf", "name": "pikepdf", "description": "PDF reading and writing", "category": "PDF"},

    # System
    {"id": "keyring", "name": "Keyring", "description": "System keyring access", "category": "System"},
    {"id": "platformdirs", "name": "Platformdirs", "description": "Platform-specific directories", "category": "System"},
    {"id": "psutil", "name": "psutil", "description": "Process and system utilities", "category": "System"},
    {"id": "python-magic", "name": "Python-Magic", "description": "File type identification", "category": "System"},
    {"id": "pyxdg", "name": "PyXDG", "description": "XDG Base Directory support", "category": "System"},
    {"id": "schedule", "name": "Schedule", "description": "Job scheduling", "category": "System"},

    # Testing
    {"id": "selenium", "name": "Selenium", "description": "Browser automation", "category": "Testing"},
    {"id": "webdriver_manager", "name": "Webdriver Manager", "description": "Manage browser drivers", "category": "Testing"},

    # Text
    {"id": "python-Levenshtein", "name": "Python-Levenshtein", "description": "Fast string matching", "category": "Text"},
    {"id": "thefuzz", "name": "TheFuzz", "description": "Fuzzy string matching", "category": "Text"},
    {"id": "Unidecode", "name": "Unidecode", "description": "Unicode to ASCII transliteration", "category": "Text"},

    # Utils
    {"id": "aenum", "name": "aenum", "description": "Advanced enumerations", "category": "Utils"},
    {"id": "fastxor", "name": "FastXOR", "description": "Fast XOR operations", "category": "Utils"},
    {"id": "packaging", "name": "Packaging", "description": "Python packaging utilities", "category": "Utils"},
    {"id": "pathlib", "name": "Pathlib", "description": "Object-oriented filesystem paths", "category": "Utils"},
    {"id": "python-dateutil", "name": "Python-Dateutil", "description": "Date/time utilities", "category": "Utils"},
    {"id": "xxhash", "name": "xxHash", "description": "Fast non-cryptographic hash", "category": "Utils"},
]

###########################################################
# Python - Local Windows
###########################################################
python[constants.EnvironmentType.LOCAL_WINDOWS] += python[constants.EnvironmentType.LOCAL_UBUNTU]
python[constants.EnvironmentType.LOCAL_WINDOWS] += [
    {"id": "pywin32", "name": "PyWin32", "description": "Windows API bindings", "category": "System"},
    {"id": "pyuac", "name": "PyUAC", "description": "Windows UAC elevation", "category": "System"},
]
