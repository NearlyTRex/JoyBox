# Imports
import os
import sys

# Local imports
import constants
import util

###########################################################
# AptGet
###########################################################
aptget = {}
aptget[constants.EnvironmentType.LOCAL_UBUNTU] = []
aptget[constants.EnvironmentType.LOCAL_WINDOWS] = []
aptget[constants.EnvironmentType.REMOTE_UBUNTU] = []
aptget[constants.EnvironmentType.REMOTE_WINDOWS] = []

###########################################################
# AptGet - Local Ubuntu
###########################################################
aptget[constants.EnvironmentType.LOCAL_UBUNTU] += [

    # Admin
    "7zip",
    "apt-file",
    "blueman",
    "clamav",
    "fuseiso",
    "jackd",
    "pulseaudio-utils",
    "qdirstat",
    "thunar",
    "unzip",
    "zip",

    # Devel
    "autoconf",
    "automake",
    "bison",
    "build-essential",
    "clang",
    "cmake",
    "dos2unix",
    "flex",
    "g++",
    "gcc",
    "gdb",
    "gettext",
    "git",
    "gitg",
    "glslang-tools",
    "golang",
    "help2man",
    "libtool-bin",
    "lld",
    "make",
    "maven",
    "nasm",
    "ninja-build",
    "npm",
    "perl-base",
    "pkg-config",
    "python3-tk",
    "python3-venv",
    "qbs",
    "qmake6",
    "qt5-qmake",
    "qt6-base-dev-tools",
    "qt6-l10n-tools",
    "qt6-tools-dev-tools",
    "qtbase5-dev-tools",
    "qttools5-dev-tools",
    "ruby-full",
    "xa65",

    # Games
    "steam",
    "steamcmd",

    # Gnome
    "brasero",
    "ghex",
    "gnome-screenshot",

    # Graphics
    "gimp",
    "ffmpeg",
    "handbrake",
    "imagemagick-6.q16",
    "imagemagick",
    "img2pdf",
    "jpegoptim",

    # Libs
    "extra-cmake-modules",
    "glslang-dev",
    "libarchive-dev",
    "libasound2-dev",
    "libavcodec-dev",
    "libavcodec-extra",
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
    "libcanberra-gtk-module",
    "libcurl4-openssl-dev",
    "libenet-dev",
    "libepoxy-dev",
    "libevdev-dev",
    "libfdk-aac-dev",
    "libflac-dev",
    "libfontconfig-dev",
    "libfreetype-dev",
    "libfreetype6-dev",
    "libgl-dev",
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
    "libpangocairo-1.0-0",
    "libpcap-dev",
    "libpipewire-0.3-dev",
    "libpixman-1-dev",
    "libpng-dev",
    "libpugixml-dev",
    "libpulse-dev",
    "libpython3-dev",
    "libqt5gamepad5-dev",
    "libqt5multimedia5-plugins",
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
    "libtidy-dev",
    "libtinyxml2-dev",
    "libudev-dev",
    "libusb-1.0-0-dev",
    "libvirt-clients",
    "libvirt-daemon-system",
    "libvorbis-dev",
    "libx11-dev",
    "libxext-dev",
    "libxi-dev",
    "libxkbfile-dev",
    "libxrandr-dev",
    "libxtst-dev",
    "libzstd-dev",
    "qml-module-qtgraphicaleffects",
    "qml-module-qtmultimedia",
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

    # Net
    "bridge-utils",
    "ca-certificates",
    "cifs-utils",
    "curl",
    "keyutils",
    "net-tools",
    "openssh-server",
    "openssl",
    "winbind",

    # Sound
    "audacity",
    "qmmp",

    # Utils
    "gsmartcontrol",
    "hardinfo",
    "jstest-gtk",
    "meld",

    # Video
    "shotcut",
    "vlc",

    # Virtualization
    "flatpak",
    "ovmf",
    "qemu-kvm",
    "qemu-utils",
    "virt-manager",
    "virtualbox-guest-additions-iso",
    "virtualbox-guest-utils",
    "virtualbox-guest-x11",
    "virtualbox",
    "xdg-desktop-portal",

    # Web
    "firefox",
    "uget",

    # X11
    "wmctrl"
]

###########################################################
# AptGet - Remote Ubuntu
###########################################################
aptget[constants.EnvironmentType.REMOTE_UBUNTU] += [

    # Admin
    "7zip",
    "apt-file",
    "unzip",
    "zip",

    # Devel
    "git",

    # Server
    "apache2-utils",
    "apache2",
    "certbot",
    "nginx",
    "nginx-common",
    "python3-certbot-nginx",

    # Net
    "curl",
    "wget",

    # Virtualization
    "docker-compose",
    "docker-compose-v2",
    "docker.io",
    "flatpak"
]
