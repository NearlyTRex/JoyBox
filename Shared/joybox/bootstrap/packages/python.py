# Local imports
import joybox.bootstrap.constants as constants
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

    # AI
    {"id": "promptc", "spec": "git+https://github.com/NearlyTRex/Assay.git", "name": "Assay", "description": "Prompt compiler: assemble, validate, measure prompts", "category": "AI"},
    {"id": "tiktoken", "name": "Tiktoken", "description": "OpenAI tokenizer, exact token counts", "category": "AI"},
    {"id": "tokenizers", "name": "Tokenizers", "description": "HuggingFace tokenizers, exact token counts", "category": "AI"},

    # API/Services
    {"id": "PySocks", "name": "PySocks", "description": "SOCKS proxy client", "category": "API"},

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
    {"id": "typer", "name": "Typer", "description": "CLI application framework", "category": "CLI"},

    # Crypto
    {"id": "cryptography", "name": "Cryptography", "description": "Cryptographic recipes and primitives", "category": "Crypto"},
    {"id": "ecdsa", "name": "ECDSA", "description": "Elliptic curve cryptography", "category": "Crypto"},
    {"id": "pycryptodome", "name": "PyCryptodome", "description": "Cryptographic library", "category": "Crypto"},
    {"id": "pycryptodomex", "name": "PyCryptodomex", "description": "Cryptographic library (standalone)", "category": "Crypto"},

    # Data
    {"id": "dictdiffer", "name": "Dictdiffer", "description": "Dictionary difference calculator", "category": "Data"},
    {"id": "json5", "name": "JSON5", "description": "JSON5 parser/serializer", "category": "Data"},
    {"id": "protobuf", "name": "Protobuf", "description": "Protocol buffers", "category": "Data"},
    {"id": "ruamel.yaml", "name": "Ruamel.YAML", "description": "YAML parser with round-trip support", "category": "Data"},

    # Dev
    {"id": "capstone", "name": "Capstone", "description": "Disassembly framework", "category": "Dev"},
    {"id": "GitPython", "name": "GitPython", "description": "Git repository interface", "category": "Dev"},
    {"id": "keystone-engine", "name": "Keystone", "description": "Assembler framework", "category": "Dev"},
    {"id": "pip", "name": "pip", "description": "Python package installer", "category": "Dev"},
    {"id": "pipenv", "name": "Pipenv", "description": "Python dev workflow tool", "category": "Dev"},
    {"id": "pyghidra", "name": "PyGhidra", "description": "Ghidra Python bindings", "category": "Dev"},
    {"id": "wheel", "name": "Wheel", "description": "Python wheel packaging", "category": "Dev"},

    # GUI
    {"id": "PyQt5", "name": "PyQt5", "description": "Qt5 bindings for Python", "category": "GUI"},

    # Parsing
    {"id": "jsonschema", "name": "JSON Schema", "description": "JSON Schema validation", "category": "Parsing"},
    {"id": "lxml", "name": "lxml", "description": "XML/HTML processing library", "category": "Parsing"},

    # PDF
    {"id": "pikepdf", "name": "pikepdf", "description": "PDF reading and writing", "category": "PDF"},

    # System
    {"id": "keyring", "name": "Keyring", "description": "System keyring access", "category": "System"},
    {"id": "platformdirs", "name": "Platformdirs", "description": "Platform-specific directories", "category": "System"},
    {"id": "pyxdg", "name": "PyXDG", "description": "XDG Base Directory support", "category": "System"},

    # Text
    {"id": "python-Levenshtein", "name": "Python-Levenshtein", "description": "Fast string matching", "category": "Text"},
    {"id": "textstat", "name": "Textstat", "description": "Readability and complexity metrics", "category": "Text"},

    # Utils
    {"id": "aenum", "name": "aenum", "description": "Advanced enumerations", "category": "Utils"},
    {"id": "fastxor", "name": "FastXOR", "description": "Fast XOR operations", "category": "Utils"},
    {"id": "packaging", "name": "Packaging", "description": "Python packaging utilities", "category": "Utils"},
    {"id": "yt-dlp-ejs", "name": "yt-dlp-ejs", "description": "yt-dlp YouTube JS challenge solver scripts", "category": "Utils"},
]

###########################################################
# Python - Local Windows
###########################################################
python[constants.EnvironmentType.LOCAL_WINDOWS] += python[constants.EnvironmentType.LOCAL_UBUNTU]
python[constants.EnvironmentType.LOCAL_WINDOWS] += [
    {"id": "pywin32", "name": "PyWin32", "description": "Windows API bindings", "category": "System"},
]
