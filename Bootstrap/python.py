# Imports
import os
import sys
import subprocess

# Local imports
import environment

###########################################################
# Packages
###########################################################
packages = [
    "aenum",
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
if environment.IsWindowsPlatform():
    packages += [
        "pywin32",
        "pyuac"
    ]

###########################################################
# Functions
###########################################################

# Setup
def Setup(ini_values = {}):

    # Get python tools
    python_exe = ini_values["Tools.Python"]["python_exe"]
    python_pip_exe = ini_values["Tools.Python"]["python_pip_exe"]
    python_install_dir = os.path.expandvars(ini_values["Tools.Python"]["python_install_dir"])
    python_tool = os.path.join(python_install_dir, python_exe)
    python_venv_dir = os.path.expandvars(ini_values["Tools.Python"]["python_venv_dir"])
    python_venv_pip_tool = os.path.join(python_venv_dir, "bin", python_pip_exe)
    if environment.IsWindowsPlatform():
        python_venv_pip_tool = os.path.join(python_venv_dir, "Scripts", python_pip_exe)

    # Create python virtual environment
    subprocess.check_call([python_tool, "-m", "venv", python_venv_dir])

    # Install python packages
    for package in packages:
        subprocess.check_call([python_venv_pip_tool, "install", "--upgrade", package])

# Run script
def RunScript(script_path, ini_values = {}):

    # Get python tools
    python_exe = ini_values["Tools.Python"]["python_exe"]
    python_venv_dir = os.path.expandvars(ini_values["Tools.Python"]["python_venv_dir"])
    python_venv_python_tool = os.path.join(python_venv_dir, "bin", python_exe)
    if environment.IsWindowsPlatform():
        python_venv_python_tool = os.path.join(python_venv_dir, "Scripts", python_exe)

    # Run python script
    subprocess.check_call([python_venv_python_tool, script_path])
