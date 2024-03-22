# Imports
import os
import sys
import subprocess

# Local imports
import environment

###########################################################
# Preliminaries
###########################################################
preliminaries = []

# Wine
if not os.path.isfile("/usr/bin/wine"):
    preliminaries += [
        "sudo dpkg --add-architecture i386",
        "sudo mkdir -pm755 /etc/apt/keyrings",
        "sudo wget -O /etc/apt/keyrings/winehq-archive.key https://dl.winehq.org/wine-builds/winehq.key"
    ]
    if "23.10" in environment.GetLinuxDistroVersion():
        preliminaries += [
            "sudo wget -NP /etc/apt/sources.list.d/ https://dl.winehq.org/wine-builds/ubuntu/dists/mantic/winehq-mantic.sources"
        ]
    elif "23.04" in environment.GetLinuxDistroVersion():
        preliminaries += [
            "sudo wget -NP /etc/apt/sources.list.d/ https://dl.winehq.org/wine-builds/ubuntu/dists/lunar/winehq-lunar.sources"
        ]
    elif "22.04" in environment.GetLinuxDistroVersion():
        preliminaries += [
            "sudo wget -NP /etc/apt/sources.list.d/ https://dl.winehq.org/wine-builds/ubuntu/dists/jammy/winehq-jammy.sources"
        ]
    elif "20.04" in environment.GetLinuxDistroVersion():
        preliminaries += [
            "sudo wget -NP /etc/apt/sources.list.d/ https://dl.winehq.org/wine-builds/ubuntu/dists/focal/winehq-focal.sources"
        ]

###########################################################
# Apt packages
###########################################################
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
    "golang",
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

    # Games
    "steam",
    "steamcmd",

    # Gnome
    "brasero",
    "ghex",
    "gnome-terminal",

    # Graphics
    "gimp",
    "handbrake",
    "imagemagick",
    "imagemagick-6.q16",
    "vlc",

    # KDE
    "dolphin",
    "dolphin-plugins",

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
    "keyutils",
    "ovmf",
    "qemu-kvm",
    "qemu-utils",
    "virtualbox",

    # Net
    "bridge-utils",
    "net-tools",

    # OtherOSFS
    "cifs-utils",

    # Perl
    "perl-base",

    # Python
    "libpython3-dev",
    "python3-tk",
    "python3-venv",

    # Sandbox
    "winehq-devel",
    "winetricks",

    # Sound
    "audacity",
    "jackd",
    "pulseaudio-utils",
    "qmmp",

    # Text
    "dos2unix",

    # Utils
    "7zip",
    "7zip-rar",
    "clamav",
    "img2pdf",
    "openssl",
    "qt6-l10n-tools",
    "zip",

    # VCS
    "git",
    "gitg",

    # Video
    "shotcut",

    # Web
    "curl",
    "firefox",

    # X11
    "qdirstat",
    "thunar",
    "wmctrl",
    "xorg-dev"
]

###########################################################
# Snap packages
###########################################################
snap_packages = [

    # Net
    "xdman --beta",

    # Text
    "codium --classic",

    # VCS
    "gitkraken --classic",

    # Web
    "discord",
    "signal-desktop",
    "telegram-desktop"
]

###########################################################
# Functions
###########################################################

# Setup
def Setup(ini_values = {}):

    # Get apt tools
    apt_exe = ini_values["Tools.Apt"]["apt_exe"]
    apt_install_dir = os.path.expandvars(ini_values["Tools.Apt"]["apt_install_dir"])
    apt_tool = os.path.join(apt_install_dir, apt_exe)

    # Get snap tools
    snap_exe = ini_values["Tools.Snap"]["snap_exe"]
    snap_install_dir = os.path.expandvars(ini_values["Tools.Snap"]["snap_install_dir"])
    snap_tool = os.path.join(snap_install_dir, snap_exe)

    # Run preliminaries
    for preliminary in preliminaries:
        subprocess.check_call(preliminary, shell=True)

    # Install apt packages
    subprocess.check_call(["sudo", apt_tool, "update"])
    for package in apt_packages:
        subprocess.check_call(["sudo", apt_tool, "-y", "install", "--install-recommends", package])

    # Install snap packages
    subprocess.check_call(["sudo", snap_tool, "refresh"])
    for package in snap_packages:
        subprocess.check_call(["sudo", snap_tool, "install"] + package.split(" "))
