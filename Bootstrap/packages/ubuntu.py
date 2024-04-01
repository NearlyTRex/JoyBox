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

# Vagrant
if not os.path.isfile("/usr/bin/vagrant"):
    preliminaries += [
        "wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg",
        "echo \"deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main\" | sudo tee /etc/apt/sources.list.d/hashicorp.list"
    ]

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
    "7zip",
    "apt-file",
    "blueman",
    "clamav",
    "jackd",
    "pulseaudio-utils",
    "qdirstat",
    "thunar",
    "zip",

    # Devel
    "autoconf",
    "automake",
    "awscli",
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
    "handbrake",
    "imagemagick-6.q16",
    "imagemagick",
    "img2pdf",

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
    "openssl",

    # Sound
    "audacity",
    "qmmp",

    # Utils
    "jstest-gtk",

    # Video
    "shotcut",
    "vlc",

    # Virtualization
    "flatpak",
    "ovmf",
    "qemu-kvm",
    "qemu-utils",
    "snapd",
    "vagrant",
    "virt-manager",
    "virtualbox",
    "winehq-devel",
    "winetricks",
    "xdg-desktop-portal",

    # Web
    "firefox",
    "uget",

    # X11
    "wmctrl"
]

###########################################################
# Snap packages
###########################################################
snap_packages = [
]

###########################################################
# Flatpak packages
###########################################################
flatpak_packages = [

    # Devel
    ["flathub", "com.axosoft.GitKraken"],
    ["flathub", "com.jetbrains.IntelliJ-IDEA-Community"],
    ["flathub", "org.mapeditor.Tiled"],

    # Text
    ["flathub", "com.vscodium.codium"],

    # Web
    ["flathub", "com.brave.Browser"],
    ["flathub", "com.discordapp.Discord"],
    ["flathub", "org.signal.Signal"],
    ["flathub", "org.telegram.desktop"]
]

###########################################################
# Functions
###########################################################

# Setup
def Setup(ini_values = {}):

    # Get apt tool
    apt_exe = ini_values["Tools.Apt"]["apt_exe"]
    apt_install_dir = os.path.expandvars(ini_values["Tools.Apt"]["apt_install_dir"])
    apt_tool = os.path.join(apt_install_dir, apt_exe)

    # Get snap tool
    snap_exe = ini_values["Tools.Snap"]["snap_exe"]
    snap_install_dir = os.path.expandvars(ini_values["Tools.Snap"]["snap_install_dir"])
    snap_tool = os.path.join(snap_install_dir, snap_exe)

    # Get flatpak tool
    flatpak_exe = ini_values["Tools.Flatpak"]["flatpak_exe"]
    flatpak_install_dir = os.path.expandvars(ini_values["Tools.Flatpak"]["flatpak_install_dir"])
    flatpak_tool = os.path.join(flatpak_install_dir, flatpak_exe)

    # Run preliminaries
    for preliminary in preliminaries:
        subprocess.check_call(preliminary, shell=True)

    # Install apt packages
    subprocess.check_call(["sudo", apt_tool, "update"])
    for package in apt_packages:
        subprocess.check_call(["sudo", apt_tool, "-y", "install", "--install-recommends", package])

    # Install snap packages
    if os.path.isfile(snap_tool):
        subprocess.check_call(["sudo", snap_tool, "refresh"])
        for package in snap_packages:
            subprocess.check_call(["sudo", snap_tool, "install"] + package)

    # Install flatpak packages
    if os.path.isfile(flatpak_tool):
        subprocess.check_call([flatpak_tool, "update", "-y"])
        for package in flatpak_packages:
            subprocess.check_call([flatpak_tool, "install", "-y"] + package)
