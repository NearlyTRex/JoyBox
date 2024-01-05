#!/usr/bin/env python3

# Imports
import os
import sys
import subprocess
import shutil
import configparser

###########################################################
# Utility
###########################################################

# Prompt for value
def PromptForValue(description, default_value):
    value = input(">>> %s [default: %s]: " % (description, default_value))
    if len(value) == 0:
        return default_value
    return value

###########################################################
# Ini
###########################################################

# Ini files
ini_filename = "JoyBox.ini"
ini_example_filename_windows = "JoyBox.windows.ini.example"
ini_example_filename_linux = "JoyBox.linux.ini.example"

# Create config parser
config = configparser.ConfigParser(interpolation=None)

# Check if ini already exists
if os.path.isfile(ini_filename):

    # Use existing data
    print("Loading ini file...")
    config.read(ini_filename)

else:

    # Read example data
    print("Loading example ini file...")
    if sys.platform.startswith("win"):
        config.read(ini_example_filename_windows)
    elif sys.platform.startswith("linux"):
        config.read(ini_example_filename_linux)

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

# Apt preliminiaries
apt_preliminiaries = [

    # Codium
    "wget -qO - https://gitlab.com/paulcarroty/vscodium-deb-rpm-repo/raw/master/pub.gpg | gpg --dearmor  | sudo dd of=/usr/share/keyrings/vscodium-archive-keyring.gpg",
    "echo 'deb [ signed-by=/usr/share/keyrings/vscodium-archive-keyring.gpg ] https://download.vscodium.com/debs vscodium main' | sudo tee /etc/apt/sources.list.d/vscodium.list",

    # Signal
    "wget -O- https://updates.signal.org/desktop/apt/keys.asc | gpg --dearmor > signal-desktop-keyring.gpg",
    "cat signal-desktop-keyring.gpg | sudo tee /usr/share/keyrings/signal-desktop-keyring.gpg > /dev/null",
    "echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/signal-desktop-keyring.gpg] https://updates.signal.org/desktop/apt xenial main' | sudo tee /etc/apt/sources.list.d/signal-xenial.list",
    "rm -f ./signal-desktop-keyring.gpg",

    # Wine
    "sudo dpkg --add-architecture i386",
    "sudo mkdir -pm755 /etc/apt/keyrings",
    "sudo wget -O /etc/apt/keyrings/winehq-archive.key https://dl.winehq.org/wine-builds/winehq.key",
    "sudo wget -NP /etc/apt/sources.list.d/ https://dl.winehq.org/wine-builds/ubuntu/dists/jammy/winehq-jammy.sources"
]

# Apt packages
apt_packages = [

    # Admin
    "apt-file",
    "libudev-dev",
    "libvirt-clients",
    "libvirt-daemon-system",
    "virt-manager",
    "xdg-desktop-portal",

    # Devel
    "autoconf",
    "automake",
    "bison",
    "build-essential",
    "clang",
    "cmake",
    "flex",
    "g++",
    "gcc",
    "gettext",
    "help2man",
    "libtool-bin",
    "lld",
    "make",
    "nasm",
    "ninja-build",
    "pkg-config",
    "qmake6",
    "qt5-qmake",
    "qt6-base-dev-tools",
    "qt6-tools-dev-tools",
    "qtbase5-dev-tools",
    "qttools5-dev-tools",
    "xa65",

    # Libdevel
    "glslang-dev",
    "glslang-tools",
    "libarchive-dev",
    "libasound2-dev",
    "libavcodec-dev",
    "libavdevice-dev",
    "libavformat-dev",
    "libavutil-dev",
    "libbluetooth-dev",
    "libboost-date-time-dev",
    "libboost-dev",
    "libboost-filesystem-dev",
    "libboost-iostreams-dev",
    "libboost-program-options-dev",
    "libboost-regex-dev",
    "libboost-system-dev",
    "libbz2-dev",
    "libcurl4-openssl-dev",
    "libepoxy-dev",
    "libevdev-dev",
    "libfdk-aac-dev",
    "libflac-dev",
    "libfontconfig-dev",
    "libfreetype-dev",
    "libfreetype6-dev",
    "libgl1-mesa-dev",
    "libglew-dev",
    "libglib2.0-dev",
    "libgtk-3-dev",
    "libgtk2.0-dev",
    "libhidapi-dev",
    "libhtmlcxx-dev",
    "libjpeg-dev",
    "libjsoncpp-dev",
    "liblzo2-dev",
    "libmbedtls-dev",
    "libminiupnpc-dev",
    "libmpeg2-4-dev",
    "libncurses-dev",
    "libopenal-dev",
    "libpcap-dev",
    "libpipewire-0.3-dev",
    "libpixman-1-dev",
    "libpng-dev",
    "libpugixml-dev",
    "libpulse-dev",
    "libqt5gamepad5-dev",
    "libqt5opengl5-dev",
    "libqt5svg5-dev",
    "libqt6opengl6-dev",
    "libqt6svg6-dev",
    "librhash-dev",
    "libsamplerate0-dev",
    "libsdl-net1.2-dev",
    "libsdl2-dev",
    "libsdl2-net-dev",
    "libsdl2-ttf-dev",
    "libsfml-dev",
    "libslirp-dev",
    "libsndio-dev",
    "libssl-dev",
    "libswscale-dev",
    "libsystemd-dev",
    "libtheora-dev",
    "libtinyxml2-dev",
    "libusb-1.0-0-dev",
    "libvorbis-dev",
    "libx11-dev",
    "libxext-dev",
    "libxi-dev",
    "libxkbfile-dev",
    "libxrandr-dev",
    "libxtst-dev",
    "libzstd-dev",
    "qt6-base-dev",
    "qt6-base-private-dev",
    "qt6-multimedia-dev",
    "qt6-tools-dev",
    "qtbase5-dev",
    "qtbase5-private-dev",
    "qtchooser",
    "qtdeclarative5-dev",
    "qtmultimedia5-dev",
    "qtwebengine5-dev",
    "zlib1g-dev",

    # Libs
    "extra-cmake-modules",
    "libavcodec-extra",
    "libcanberra-gtk-module",
    "libgl-dev",
    "libpangocairo-1.0-0",
    "libqt5multimedia5-plugins",
    "qml-module-qtgraphicaleffects",
    "qml-module-qtmultimedia",

    # Misc
    "ca-certificates",
    "ovmf",
    "qemu-kvm",
    "qemu-utils",
    "virtualbox",

    # Net
    "bridge-utils",

    # Perl
    "perl-base",

    # Python
    "libpython3-dev",
    "python3-venv",

    # Sandbox
    "winehq-devel",

    # Sound
    "jackd",

    # Text
    "codium",
    "dos2unix",

    # Utils
    "openssl",
    "p7zip-full",
    "qt6-l10n-tools",
    "zip",

    # VCS
    "git",
    "gitg",

    # Web
    "curl",
    "firefox",
    "signal-desktop",
    "telegram-desktop",

    # X11
    "qdirstat",
    "xorg-dev"
]

# Install apt preliminiaries
if apt_tool and os.path.isfile(apt_tool):
    for apt_preliminiary in apt_preliminiaries:
        subprocess.run(apt_preliminiary, shell=True)

# Install apt packages
if apt_tool and os.path.isfile(apt_tool):
    subprocess.run(["sudo", apt_tool, "update"])
    for apt_package in apt_packages:
        subprocess.run(["sudo", apt_tool, "-y", "install", "--install-recommends", apt_package])

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

    # Net
    "subhra74.XtremeDownloadManager",

    # Perl
    "StrawberryPerl.StrawberryPerl",

    # Python
    "Python.Python.3.11",

    # Sandbox
    "Sandboxie.Plus",

    # Text
    "VSCodium.VSCodium",

    # Utils
    "mcmilk.7zip-zstd",

    # VCS
    "Git.Git",
    "TortoiseGit.TortoiseGit",

    # Web
    "Discord.Discord",
    "Mozilla.Firefox",
    "OpenWhisperSystems.Signal",
    "Telegram.TelegramDesktop"
]

# Install winget packages
if winget_tool and os.path.isfile(winget_tool):
    for winget_package in winget_packages:
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
print(">>> On Linux: export PATH=\"%s:$PATH\"" % scripts_bin_dir)
print(">>> On Windows: setx PATH \"%%PATH%%;%s\"" % scripts_bin_dir)
