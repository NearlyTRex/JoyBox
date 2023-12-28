# Imports
import os
import sys
import subprocess
import shutil
import configparser

###########################################################
# Ini
###########################################################

# Ini files
ini_filename = "JoyBox.ini"
ini_example_filename_windows = "JoyBox.windows.ini.example"
ini_example_filename_linux = "JoyBox.linux.ini.example"

# Create config
config = configparser.ConfigParser()
if sys.platform.startswith("win"):
    config.read(ini_example_filename_windows)
elif sys.platform.startswith("linux"):
    config.read(ini_example_filename_linux)

# Prompt for value
def PromptForValue(description, default_value):
    value = input(">>> %s [default: %s]: " % (description, default_value))
    if len(value) == 0:
        return default_value
    return value

# Create ini file
print("Creating ini file...")
for userdata_section in config.sections():
    for userdata_key in config[userdata_section]:
        config[userdata_section][userdata_key] = PromptForValue(userdata_key, config[userdata_section][userdata_key])
with open(ini_filename, "w") as f:
  config.write(f)

###########################################################
# Apt
###########################################################

# Apt tool
apt_tool = None
if "Tools.Apt" in config:
    apt_exe = config["Tools.Apt"]["apt_exe"]
    apt_install_dir = os.path.expandvars(config["Tools.Apt"]["apt_install_dir"])
    apt_tool = os.path.join(apt_install_dir, apt_exe)

# Apt packages
apt_packages = [

    # Building
    "autoconf",
    "automake",
    "build-essential",
    "clang",
    "cmake",
    "extra-cmake-modules",
    "g++",
    "gcc",
    "libtool-bin",
    "lld",
    "make",
    "nasm",
    "ninja-build",
    "pkg-config",
    "xa65",

    # Tools
    "bison",
    "curl",
    "dos2unix",
    "firefox",
    "flex",
    "gettext",
    "git",
    "openssl",
    "p7zip-full",
    "zip",
    "perl-base",
    "winehq-devel",

    # GTK
    "libcanberra-gtk-module",
    "libglib2.0-dev",
    "libgtk-3-dev",
    "libgtk2.0-dev",

    # SDL
    "libsdl-net1.2-dev",
    "libsdl2-dev",
    "libsdl2-net-dev",
    "libsdl2-ttf-dev",

    # SFML
    "libsfml-dev",

    # Qt
    "libqt5gamepad5-dev",
    "libqt5multimedia5-plugins",
    "libqt5opengl5-dev",
    "libqt5svg5-dev",
    "libqt6opengl6-dev",
    "libqt6svg6-dev",
    "qmake6",
    "qml-module-qtgraphicaleffects",
    "qml-module-qtmultimedia",
    "qt5-qmake",
    "qt6-base-dev",
    "qt6-base-dev-tools",
    "qt6-base-private-dev",
    "qt6-l10n-tools",
    "qt6-multimedia-dev",
    "qt6-tools-dev",
    "qt6-tools-dev-tools",
    "qtbase5-dev",
    "qtbase5-dev-tools",
    "qtbase5-private-dev",
    "qtchooser",
    "qtdeclarative5-dev",
    "qtmultimedia5-dev",
    "qttools5-dev-tools",

    # OpenGL
    "glslang-dev",
    "glslang-tools",
    "libepoxy-dev",
    "libgl-dev",
    "libgl1-mesa-dev",
    "libglew-dev",

    # XML
    "libpugixml-dev",

    # Security
    "ca-certificates",
    "libmbedtls-dev",
    "libssl-dev",

    # Compression
    "libarchive-dev",
    "libbz2-dev",
    "liblzo2-dev",
    "libzstd-dev",
    "zlib1g-dev",

    # Audiovisual
    "jackd",
    "libasound-dev",
    "libasound2-dev",
    "libavcodec-dev",
    "libavcodec-extra",
    "libavdevice-dev",
    "libavformat-dev",
    "libavutil-dev",
    "libfdk-aac-dev",
    "libflac-dev",
    "libfontconfig-dev",
    "libfreetype-dev",
    "libfreetype6-dev",
    "libjpeg-dev",
    "libmpeg2-4-dev",
    "libncurses-dev",
    "libopenal-dev",
    "libpangocairo-1.0-0",
    "libpipewire-0.3-dev",
    "libpixman-1-dev",
    "libpng-dev",
    "libpulse-dev",
    "libsamplerate0-dev",
    "libsndio-dev",
    "libswscale-dev",
    "libtheora-dev",
    "libvorbis-dev",
    "libx11-dev",
    "libxext-dev",
    "libxrandr-dev",
    "xdg-desktop-portal",
    "xorg-dev",

    # Input
    "libbluetooth-dev",
    "libevdev-dev",
    "libhidapi-dev",
    "libsystemd-dev",
    "libudev-dev",
    "libusb-1.0-0-dev",
    "libxi-dev",
    "libxkbfile-dev",
    "libxtst-dev",

    # Networking
    "bridge-utils",
    "libcurl4-openssl-dev",
    "libminiupnpc-dev",
    "libpcap-dev",
    "libslirp-dev",

    # Virtual machines
    "libvirt-clients",
    "libvirt-daemon-system",
    "ovmf",
    "qemu-kvm",
    "qemu-utils",
    "virt-manager",
    "virtualbox"
]

# Install apt packages
if apt_tool and os.path.isfile(apt_tool):
    for apt_package in apt_packages:
        subprocess.run(["sudo", apt_tool, "-y", "install", apt_package])

###########################################################
# WinGet
###########################################################

# WinGet tool
winget_tool = None
if "Tools.WinGet" in config:
    winget_exe = config["Tools.WinGet"]["winget_exe"]
    winget_install_dir = os.path.expandvars(config["Tools.WinGet"]["winget_install_dir"])
    winget_tool = os.path.join(winget_install_dir, winget_exe)

# WinGet packages
winget_packages = [
    "Git.Git",
    "Mozilla.Firefox",
    "Sandboxie.Plus",
    "mcmilk.7zip-zstd",
    "Python.Python.3.11",
    "StrawberryPerl.StrawberryPerl"
]

# Install winget packages
if winget_tool and os.path.isfile(winget_tool):
    for winget_package in config.winget_packages:
        subprocess.run([winget_tool, "install", "-e", "--id", winget_package])

###########################################################
# Python
###########################################################

# Python packages
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
python_packages_windows = [
    "pywin32",
    "pyuac"
]
python_packages_linux = []
if sys.platform.startswith("win"):
    python_packages += python_packages_windows
elif sys.platform.startswith("linux"):
    python_packages += python_packages_linux

# Python tool
python_exe = config["Tools.Python"]["python_exe"]
python_pip_exe = config["Tools.Python"]["python_pip_exe"]
python_install_dir = os.path.expandvars(config["Tools.Python"]["python_install_dir"])
python_venv_dir = os.path.expandvars(config["Tools.Python"]["python_venv_dir"])
python_tool = os.path.join(python_install_dir, python_exe)

# Python virtual environment tool
python_venv_python_tool = os.path.join(python_venv_dir, "bin", python_exe)
python_venv_pip_tool = os.path.join(python_venv_dir, "bin", python_pip_exe)
if sys.platform.startswith("win"):
    python_venv_python_tool = os.path.join(python_venv_dir, "Scripts", python_exe)
    python_venv_pip_tool = os.path.join(python_venv_dir, "Scripts", python_pip_exe)

# Create python virtual environment
subprocess.run([python_tool, "-m", "venv", python_venv_dir])

# Install python packages
for python_package in python_packages:
    subprocess.run([python_venv_pip_tool, "install", "--upgrade", python_package])

###########################################################
# Environment
###########################################################

# Get environment script
scripts_bin_dir = os.path.realpath(os.path.join(".", "Scripts", "bin"))
environment_script = os.path.join(scripts_bin_dir, "setup_environment.py")

# Run environment script
subprocess.run([python_venv_python_tool, environment_script])

# Inform user
print("Bootstrap complete!")
print("Add %s to your PATH to run scripts" % scripts_bin_dir)
