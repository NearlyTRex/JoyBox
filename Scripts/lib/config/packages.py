# Imports
import os
import sys

# Required system packages
required_system_packages_windows = []
required_system_packages_linux = [

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
    "dos2unix",
    "ffmpeg",
    "flex",
    "gettext",
    "git",
    "openssl",
    "zip",

    # GTK
    "libcanberra-gtk-module",
    "libgtk-3-dev",
    "libgtk2.0-dev",

    # SDL
    "libsdl-net1.2-dev",
    "libsdl2-dev",
    "libsdl2-net-dev",
    "libsdl2-ttf-dev",

    # SFML
    "libsfml-dev",

    # Qt5
    "libqt5gamepad5-dev",
    "libqt5multimedia5-plugins",
    "libqt5opengl5-dev",
    "libqt5svg5-dev",
    "qt5-qmake",
    "qtbase5-dev-tools",
    "qtbase5-dev",
    "qtbase5-private-dev",
    "qtdeclarative5-dev",
    "qtmultimedia5-dev",
    "qttools5-dev-tools",

    # Qt6
    "libqt6opengl6-dev",
    "libqt6svg6-dev",
    "qmake6",
    "qt6-base-dev-tools",
    "qt6-base-dev",
    "qt6-base-private-dev",
    "qt6-l10n-tools",
    "qt6-multimedia-dev",
    "qt6-tools-dev-tools",
    "qt6-tools-dev",

    # Qt
    "qml-module-qtgraphicaleffects",
    "qml-module-qtmultimedia",
    "qtchooser",

    # OpenGL
    "glslang-dev",
    "glslang-tools",
    "libepoxy-dev",
    "libgl-dev",
    "libgl1-mesa-dev",
    "libglew-dev",

    # Python
    "python3-tk",
    "python3-yaml",

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
    "virtualbox",

    # Utility
    "libglib2.0-dev",
    "libpugixml-dev",
    "xdg-desktop-portal"
]
required_system_packages_all = []
