#!/bin/bash

# Building
sudo apt-get -y install autoconf
sudo apt-get -y install automake
sudo apt-get -y install build-essential
sudo apt-get -y install clang
sudo apt-get -y install cmake
sudo apt-get -y install extra-cmake-modules
sudo apt-get -y install g++
sudo apt-get -y install gcc
sudo apt-get -y install libtool-bin
sudo apt-get -y install lld
sudo apt-get -y install make
sudo apt-get -y install nasm
sudo apt-get -y install ninja-build
sudo apt-get -y install pkg-config
sudo apt-get -y install xa65

# Tools
sudo apt-get -y install bison
sudo apt-get -y install curl
sudo apt-get -y install dos2unix
sudo apt-get -y install firefox
sudo apt-get -y install flex
sudo apt-get -y install gettext
sudo apt-get -y install git
sudo apt-get -y install openssl
sudo apt-get -y install p7zip-full
sudo apt-get -y install zip
sudo apt-get -y install python3-minimal

# GTK
sudo apt-get -y install libcanberra-gtk-module
sudo apt-get -y install libglib2.0-dev
sudo apt-get -y install libgtk-3-dev
sudo apt-get -y install libgtk2.0-dev

# SDL
sudo apt-get -y install libsdl-net1.2-dev
sudo apt-get -y install libsdl2-dev
sudo apt-get -y install libsdl2-net-dev
sudo apt-get -y install libsdl2-ttf-dev

# SFML
sudo apt-get -y install libsfml-dev

# Qt
sudo apt-get -y install libqt5gamepad5-dev
sudo apt-get -y install libqt5multimedia5-plugins
sudo apt-get -y install libqt5opengl5-dev
sudo apt-get -y install libqt5svg5-dev
sudo apt-get -y install libqt6opengl6-dev
sudo apt-get -y install libqt6svg6-dev
sudo apt-get -y install qmake6
sudo apt-get -y install qml-module-qtgraphicaleffects
sudo apt-get -y install qml-module-qtmultimedia
sudo apt-get -y install qt5-qmake
sudo apt-get -y install qt6-base-dev
sudo apt-get -y install qt6-base-dev-tools
sudo apt-get -y install qt6-base-private-dev
sudo apt-get -y install qt6-l10n-tools
sudo apt-get -y install qt6-multimedia-dev
sudo apt-get -y install qt6-tools-dev
sudo apt-get -y install qt6-tools-dev-tools
sudo apt-get -y install qtbase5-dev
sudo apt-get -y install qtbase5-dev-tools
sudo apt-get -y install qtbase5-private-dev
sudo apt-get -y install qtchooser
sudo apt-get -y install qtdeclarative5-dev
sudo apt-get -y install qtmultimedia5-dev
sudo apt-get -y install qttools5-dev-tools

# OpenGL
sudo apt-get -y install glslang-dev
sudo apt-get -y install glslang-tools
sudo apt-get -y install libepoxy-dev
sudo apt-get -y install libgl-dev
sudo apt-get -y install libgl1-mesa-dev
sudo apt-get -y install libglew-dev

# XML
sudo apt-get -y install libpugixml-dev

# Security
sudo apt-get -y install ca-certificates
sudo apt-get -y install libmbedtls-dev
sudo apt-get -y install libssl-dev

# Compression
sudo apt-get -y install libarchive-dev
sudo apt-get -y install libbz2-dev
sudo apt-get -y install liblzo2-dev
sudo apt-get -y install libzstd-dev
sudo apt-get -y install zlib1g-dev

# Audiovisual
sudo apt-get -y install jackd
sudo apt-get -y install libasound-dev
sudo apt-get -y install libasound2-dev
sudo apt-get -y install libavcodec-dev
sudo apt-get -y install libavcodec-extra
sudo apt-get -y install libavdevice-dev
sudo apt-get -y install libavformat-dev
sudo apt-get -y install libavutil-dev
sudo apt-get -y install libfdk-aac-dev
sudo apt-get -y install libflac-dev
sudo apt-get -y install libfontconfig-dev
sudo apt-get -y install libfreetype-dev
sudo apt-get -y install libfreetype6-dev
sudo apt-get -y install libjpeg-dev
sudo apt-get -y install libmpeg2-4-dev
sudo apt-get -y install libncurses-dev
sudo apt-get -y install libopenal-dev
sudo apt-get -y install libpangocairo-1.0-0
sudo apt-get -y install libpipewire-0.3-dev
sudo apt-get -y install libpixman-1-dev
sudo apt-get -y install libpng-dev
sudo apt-get -y install libpulse-dev
sudo apt-get -y install libsamplerate0-dev
sudo apt-get -y install libsndio-dev
sudo apt-get -y install libswscale-dev
sudo apt-get -y install libtheora-dev
sudo apt-get -y install libvorbis-dev
sudo apt-get -y install libx11-dev
sudo apt-get -y install libxext-dev
sudo apt-get -y install libxrandr-dev
sudo apt-get -y install xdg-desktop-portal
sudo apt-get -y install xorg-dev

# Input
sudo apt-get -y install libbluetooth-dev
sudo apt-get -y install libevdev-dev
sudo apt-get -y install libhidapi-dev
sudo apt-get -y install libsystemd-dev
sudo apt-get -y install libudev-dev
sudo apt-get -y install libusb-1.0-0-dev
sudo apt-get -y install libxi-dev
sudo apt-get -y install libxkbfile-dev
sudo apt-get -y install libxtst-dev

# Networking
sudo apt-get -y install bridge-utils
sudo apt-get -y install libcurl4-openssl-dev
sudo apt-get -y install libminiupnpc-dev
sudo apt-get -y install libpcap-dev
sudo apt-get -y install libslirp-dev

# Virtual machines
sudo apt-get -y install libvirt-clients
sudo apt-get -y install libvirt-daemon-system
sudo apt-get -y install ovmf
sudo apt-get -y install qemu-kvm
sudo apt-get -y install qemu-utils
sudo apt-get -y install virt-manager
sudo apt-get -y install virtualbox

# Python
python -m venv $HOME/.venv
$HOME/.venv/Scripts/pip install --upgrade pip
$HOME/.venv/Scripts/pip install --upgrade wheel
$HOME/.venv/Scripts/pip install --upgrade psutil
$HOME/.venv/Scripts/pip install --upgrade selenium
$HOME/.venv/Scripts/pip install --upgrade requests
$HOME/.venv/Scripts/pip install --upgrade pathlib
$HOME/.venv/Scripts/pip install --upgrade PySimpleGUI
$HOME/.venv/Scripts/pip install --upgrade Pillow
$HOME/.venv/Scripts/pip install --upgrade bs4
$HOME/.venv/Scripts/pip install --upgrade lxml
$HOME/.venv/Scripts/pip install --upgrade mergedeep
$HOME/.venv/Scripts/pip install --upgrade fuzzywuzzy
$HOME/.venv/Scripts/pip install --upgrade dictdiffer
$HOME/.venv/Scripts/pip install --upgrade termcolor
$HOME/.venv/Scripts/pip install --upgrade pycryptodome
$HOME/.venv/Scripts/pip install --upgrade pycryptodomex
$HOME/.venv/Scripts/pip install --upgrade cryptography
$HOME/.venv/Scripts/pip install --upgrade aenum
$HOME/.venv/Scripts/pip install --upgrade fastxor
$HOME/.venv/Scripts/pip install --upgrade packaging
$HOME/.venv/Scripts/pip install --upgrade ecdsa
$HOME/.venv/Scripts/pip install --upgrade schedule
$HOME/.venv/Scripts/pip install --upgrade python-dateutil
$HOME/.venv/Scripts/pip install --upgrade xxhash
$HOME/.venv/Scripts/pip install --upgrade screeninfo
$HOME/.venv/Scripts/pip install --upgrade tqdm
