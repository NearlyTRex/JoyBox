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
    {"id": "7zip", "name": "7-Zip", "description": "High compression file archiver", "category": "Admin"},
    {"id": "7zip-standalone", "name": "7-Zip Standalone", "description": "Standalone 7-Zip binary", "category": "Admin"},
    {"id": "apt-file", "name": "apt-file", "description": "Search for files in apt packages", "category": "Admin"},
    {"id": "baobab", "name": "Disk Usage Analyzer", "description": "Graphical disk usage analyzer", "category": "Admin"},
    {"id": "blueman", "name": "Blueman", "description": "Bluetooth manager", "category": "Admin"},
    {"id": "clamav", "name": "ClamAV", "description": "Antivirus scanner", "category": "Admin"},
    {"id": "file-roller", "name": "File Roller", "description": "Archive manager", "category": "Admin"},
    {"id": "fuseiso", "name": "FuseISO", "description": "Mount ISO images", "category": "Admin"},
    {"id": "jackd", "name": "JACK", "description": "Low-latency audio server", "category": "Admin"},
    {"id": "pulseaudio-utils", "name": "PulseAudio Utils", "description": "PulseAudio command line tools", "category": "Admin"},
    {"id": "qdirstat", "name": "QDirStat", "description": "Disk usage statistics", "category": "Admin"},
    {"id": "thunar", "name": "Thunar", "description": "XFCE file manager", "category": "Admin"},
    {"id": "unzip", "name": "unzip", "description": "Extract ZIP archives", "category": "Admin"},
    {"id": "zip", "name": "zip", "description": "Create ZIP archives", "category": "Admin"},
    {"id": "zsh", "name": "Zsh", "description": "Z shell", "category": "Admin"},

    # Devel
    {"id": "astyle", "name": "Artistic Style", "description": "Source code formatter", "category": "Devel"},
    {"id": "autoconf", "name": "Autoconf", "description": "Configure script generator", "category": "Devel"},
    {"id": "automake", "name": "Automake", "description": "Makefile generator", "category": "Devel"},
    {"id": "bison", "name": "Bison", "description": "Parser generator", "category": "Devel"},
    {"id": "build-essential", "name": "Build Essential", "description": "C/C++ compiler and tools", "category": "Devel"},
    {"id": "ccache", "name": "ccache", "description": "Compiler cache for faster rebuilds", "category": "Devel"},
    {"id": "clang", "name": "Clang", "description": "LLVM C/C++ compiler", "category": "Devel"},
    {"id": "clang-format", "name": "clang-format", "description": "C/C++ code formatter", "category": "Devel"},
    {"id": "cmake", "name": "CMake", "description": "Cross-platform build system", "category": "Devel"},
    {"id": "dkms", "name": "DKMS", "description": "Dynamic kernel module support", "category": "Devel"},
    {"id": "dos2unix", "name": "dos2unix", "description": "Line ending converter", "category": "Devel"},
    {"id": "dotnet-sdk-8.0", "name": ".NET SDK 8.0", "description": "Microsoft .NET SDK", "category": "Devel"},
    {"id": "fd-find", "name": "fd", "description": "Fast file finder", "category": "Devel"},
    {"id": "flex", "name": "Flex", "description": "Lexical analyzer generator", "category": "Devel"},
    {"id": "g++", "name": "G++", "description": "GNU C++ compiler", "category": "Devel"},
    {"id": "gcc", "name": "GCC", "description": "GNU C compiler", "category": "Devel"},
    {"id": "gdb", "name": "GDB", "description": "GNU debugger", "category": "Devel"},
    {"id": "gettext", "name": "gettext", "description": "Internationalization tools", "category": "Devel"},
    {"id": "git", "name": "Git", "description": "Version control system", "category": "Devel"},
    {"id": "gitg", "name": "gitg", "description": "GNOME Git client", "category": "Devel"},
    {"id": "glslang-tools", "name": "glslang", "description": "GLSL shader compiler", "category": "Devel"},
    {"id": "golang", "name": "Go", "description": "Go programming language", "category": "Devel"},
    {"id": "graphviz", "name": "Graphviz", "description": "Graph visualization", "category": "Devel"},
    {"id": "help2man", "name": "help2man", "description": "Generate man pages", "category": "Devel"},
    {"id": "jq", "name": "jq", "description": "JSON processor", "category": "Devel"},
    {"id": "libtool-bin", "name": "Libtool", "description": "Library build tool", "category": "Devel"},
    {"id": "lld", "name": "LLD", "description": "LLVM linker", "category": "Devel"},
    {"id": "make", "name": "Make", "description": "Build automation tool", "category": "Devel"},
    {"id": "maven", "name": "Maven", "description": "Java build tool", "category": "Devel"},
    {"id": "nasm", "name": "NASM", "description": "Netwide assembler", "category": "Devel"},
    {"id": "ninja-build", "name": "Ninja", "description": "Fast build system", "category": "Devel"},
    {"id": "nodejs", "name": "Node.js", "description": "JavaScript runtime", "category": "Devel"},
    {"id": "npm", "name": "npm", "description": "Node package manager", "category": "Devel"},
    {"id": "openjdk-21-jdk", "name": "OpenJDK 21", "description": "Java Development Kit 21", "category": "Devel"},
    {"id": "perl-base", "name": "Perl", "description": "Perl interpreter", "category": "Devel"},
    {"id": "pkg-config", "name": "pkg-config", "description": "Library compile flags helper", "category": "Devel"},
    {"id": "python3-pip", "name": "pip", "description": "Python package installer", "category": "Devel"},
    {"id": "python3-tk", "name": "Python Tkinter", "description": "Python GUI toolkit", "category": "Devel"},
    {"id": "python3-venv", "name": "Python venv", "description": "Python virtual environments", "category": "Devel"},
    {"id": "qbs", "name": "Qbs", "description": "Qt build suite", "category": "Devel"},
    {"id": "qmake6", "name": "qmake (Qt6)", "description": "Qt6 build tool", "category": "Devel"},
    {"id": "qt5-qmake", "name": "qmake (Qt5)", "description": "Qt5 build tool", "category": "Devel"},
    {"id": "qt6-base-dev-tools", "name": "Qt6 Dev Tools", "description": "Qt6 development tools", "category": "Devel"},
    {"id": "qt6-l10n-tools", "name": "Qt6 L10n Tools", "description": "Qt6 localization tools", "category": "Devel"},
    {"id": "qt6-tools-dev-tools", "name": "Qt6 Tools", "description": "Qt6 additional tools", "category": "Devel"},
    {"id": "qtbase5-dev-tools", "name": "Qt5 Dev Tools", "description": "Qt5 development tools", "category": "Devel"},
    {"id": "qttools5-dev-tools", "name": "Qt5 Tools", "description": "Qt5 additional tools", "category": "Devel"},
    {"id": "ruby-full", "name": "Ruby", "description": "Ruby programming language", "category": "Devel"},
    {"id": "xa65", "name": "xa65", "description": "6502 cross-assembler", "category": "Devel"},

    # Gnome
    {"id": "brasero", "name": "Brasero", "description": "CD/DVD burning", "category": "Gnome"},
    {"id": "eog", "name": "Eye of GNOME", "description": "Image viewer", "category": "Gnome"},
    {"id": "evince", "name": "Evince", "description": "Document viewer", "category": "Gnome"},
    {"id": "geary", "name": "Geary", "description": "Email client", "category": "Gnome"},
    {"id": "gedit", "name": "gedit", "description": "Text editor", "category": "Gnome"},
    {"id": "ghex", "name": "GHex", "description": "Hex editor", "category": "Gnome"},
    {"id": "gnome-screenshot", "name": "GNOME Screenshot", "description": "Screenshot tool", "category": "Gnome"},

    # Graphics
    {"id": "bchunk", "name": "bchunk", "description": "CD image converter", "category": "Graphics"},
    {"id": "cdrdao", "name": "cdrdao", "description": "CD burning tool", "category": "Graphics"},
    {"id": "gimp", "name": "GIMP", "description": "Image editor", "category": "Graphics"},
    {"id": "ffmpeg", "name": "FFmpeg", "description": "Video/audio converter", "category": "Graphics"},
    {"id": "handbrake", "name": "HandBrake", "description": "Video transcoder", "category": "Graphics"},
    {"id": "imagemagick-6.q16", "name": "ImageMagick Q16", "description": "Image manipulation (16-bit)", "category": "Graphics"},
    {"id": "imagemagick", "name": "ImageMagick", "description": "Image manipulation tools", "category": "Graphics"},
    {"id": "img2pdf", "name": "img2pdf", "description": "Image to PDF converter", "category": "Graphics"},
    {"id": "jpegoptim", "name": "jpegoptim", "description": "JPEG optimizer", "category": "Graphics"},

    # Libs - Development libraries (simplified descriptions)
    {"id": "extra-cmake-modules", "category": "Libs"},
    {"id": "glslang-dev", "category": "Libs"},
    {"id": "libarchive-dev", "category": "Libs"},
    {"id": "libasound2-dev", "category": "Libs"},
    {"id": "libavcodec-dev", "category": "Libs"},
    {"id": "libavcodec-extra", "category": "Libs"},
    {"id": "libavdevice-dev", "category": "Libs"},
    {"id": "libavformat-dev", "category": "Libs"},
    {"id": "libavutil-dev", "category": "Libs"},
    {"id": "libbluetooth-dev", "category": "Libs"},
    {"id": "libboost-date-time-dev", "category": "Libs"},
    {"id": "libboost-dev", "category": "Libs"},
    {"id": "libboost-filesystem-dev", "category": "Libs"},
    {"id": "libboost-iostreams-dev", "category": "Libs"},
    {"id": "libboost-program-options-dev", "category": "Libs"},
    {"id": "libboost-regex-dev", "category": "Libs"},
    {"id": "libboost-system-dev", "category": "Libs"},
    {"id": "libbz2-dev", "category": "Libs"},
    {"id": "libcanberra-gtk-module", "category": "Libs"},
    {"id": "libcurl4-openssl-dev", "category": "Libs"},
    {"id": "libenet-dev", "category": "Libs"},
    {"id": "libepoxy-dev", "category": "Libs"},
    {"id": "libevdev-dev", "category": "Libs"},
    {"id": "libfdk-aac-dev", "category": "Libs"},
    {"id": "libflac-dev", "category": "Libs"},
    {"id": "libfontconfig-dev", "category": "Libs"},
    {"id": "libfreetype-dev", "category": "Libs"},
    {"id": "libfreetype6-dev", "category": "Libs"},
    {"id": "libgl-dev", "category": "Libs"},
    {"id": "libgl1-mesa-dev", "category": "Libs"},
    {"id": "libglew-dev", "category": "Libs"},
    {"id": "libglib2.0-dev", "category": "Libs"},
    {"id": "libgtk-3-dev", "category": "Libs"},
    {"id": "libgtk2.0-dev", "category": "Libs"},
    {"id": "libhidapi-dev", "category": "Libs"},
    {"id": "libhtmlcxx-dev", "category": "Libs"},
    {"id": "libjpeg-dev", "category": "Libs"},
    {"id": "libjsoncpp-dev", "category": "Libs"},
    {"id": "liblzo2-dev", "category": "Libs"},
    {"id": "libmbedtls-dev", "category": "Libs"},
    {"id": "libminiupnpc-dev", "category": "Libs"},
    {"id": "libmpeg2-4-dev", "category": "Libs"},
    {"id": "libncurses-dev", "category": "Libs"},
    {"id": "libopenal-dev", "category": "Libs"},
    {"id": "libpangocairo-1.0-0", "category": "Libs"},
    {"id": "libpcap-dev", "category": "Libs"},
    {"id": "libpipewire-0.3-dev", "category": "Libs"},
    {"id": "libpixman-1-dev", "category": "Libs"},
    {"id": "libpng-dev", "category": "Libs"},
    {"id": "libpugixml-dev", "category": "Libs"},
    {"id": "libpulse-dev", "category": "Libs"},
    {"id": "libpython3-dev", "category": "Libs"},
    {"id": "libqt5gamepad5-dev", "category": "Libs"},
    {"id": "libqt5multimedia5-plugins", "category": "Libs"},
    {"id": "libqt5opengl5-dev", "category": "Libs"},
    {"id": "libqt5svg5-dev", "category": "Libs"},
    {"id": "libqt6opengl6-dev", "category": "Libs"},
    {"id": "libqt6svg6-dev", "category": "Libs"},
    {"id": "librhash-dev", "category": "Libs"},
    {"id": "libsamplerate0-dev", "category": "Libs"},
    {"id": "libsdl-net1.2-dev", "category": "Libs"},
    {"id": "libsdl2-dev", "category": "Libs"},
    {"id": "libsdl2-net-dev", "category": "Libs"},
    {"id": "libsdl2-ttf-dev", "category": "Libs"},
    {"id": "libsfml-dev", "category": "Libs"},
    {"id": "libslirp-dev", "category": "Libs"},
    {"id": "libsndio-dev", "category": "Libs"},
    {"id": "libssl-dev", "category": "Libs"},
    {"id": "libswscale-dev", "category": "Libs"},
    {"id": "libsystemd-dev", "category": "Libs"},
    {"id": "libtheora-dev", "category": "Libs"},
    {"id": "libtidy-dev", "category": "Libs"},
    {"id": "libtinyxml2-dev", "category": "Libs"},
    {"id": "libudev-dev", "category": "Libs"},
    {"id": "libusb-1.0-0-dev", "category": "Libs"},
    {"id": "libvirt-clients", "category": "Libs"},
    {"id": "libvirt-daemon-system", "category": "Libs"},
    {"id": "libvorbis-dev", "category": "Libs"},
    {"id": "libx11-dev", "category": "Libs"},
    {"id": "libxext-dev", "category": "Libs"},
    {"id": "libxi-dev", "category": "Libs"},
    {"id": "libxkbfile-dev", "category": "Libs"},
    {"id": "libxrandr-dev", "category": "Libs"},
    {"id": "libxtst-dev", "category": "Libs"},
    {"id": "libzstd-dev", "category": "Libs"},
    {"id": "qml-module-qtgraphicaleffects", "category": "Libs"},
    {"id": "qml-module-qtmultimedia", "category": "Libs"},
    {"id": "qml-module-qtquick2", "category": "Libs"},
    {"id": "qml-module-qtquick-controls2", "category": "Libs"},
    {"id": "qml-module-qtquick-layouts", "category": "Libs"},
    {"id": "qml-module-qtquick-window2", "category": "Libs"},
    {"id": "qt6-base-dev", "category": "Libs"},
    {"id": "qt6-base-private-dev", "category": "Libs"},
    {"id": "qt6-declarative-dev", "category": "Libs"},
    {"id": "qt6-declarative-dev-tools", "category": "Libs"},
    {"id": "qt6-multimedia-dev", "category": "Libs"},
    {"id": "qt6-tools-dev", "category": "Libs"},
    {"id": "qtbase5-dev", "category": "Libs"},
    {"id": "qtbase5-private-dev", "category": "Libs"},
    {"id": "qtchooser", "category": "Libs"},
    {"id": "qtdeclarative5-dev", "category": "Libs"},
    {"id": "qtmultimedia5-dev", "category": "Libs"},
    {"id": "qtwebengine5-dev", "category": "Libs"},
    {"id": "zlib1g-dev", "category": "Libs"},

    # Net
    {"id": "bridge-utils", "name": "bridge-utils", "description": "Network bridge utilities", "category": "Net"},
    {"id": "ca-certificates", "name": "CA Certificates", "description": "SSL certificate authorities", "category": "Net"},
    {"id": "cifs-utils", "name": "CIFS Utils", "description": "SMB/CIFS mount utilities", "category": "Net"},
    {"id": "curl", "name": "cURL", "description": "URL transfer tool", "category": "Net"},
    {"id": "keyutils", "name": "keyutils", "description": "Kernel key management", "category": "Net"},
    {"id": "net-tools", "name": "net-tools", "description": "Network utilities (ifconfig, etc.)", "category": "Net"},
    {"id": "openssh-server", "name": "OpenSSH Server", "description": "SSH server", "category": "Net"},
    {"id": "openssl", "name": "OpenSSL", "description": "SSL/TLS toolkit", "category": "Net"},
    {"id": "winbind", "name": "Winbind", "description": "Windows domain integration", "category": "Net"},

    # Sound
    {"id": "audacity", "name": "Audacity", "description": "Audio editor", "category": "Sound"},
    {"id": "easytag", "name": "EasyTag", "description": "Audio tag editor", "category": "Sound"},
    {"id": "fluidsynth", "name": "FluidSynth", "description": "SoundFont synthesizer", "category": "Sound"},
    {"id": "qmmp", "name": "Qmmp", "description": "Audio player (Winamp-like)", "category": "Sound"},

    # Utils
    {"id": "dolphin", "name": "Dolphin", "description": "KDE file manager", "category": "Utils"},
    {"id": "gsmartcontrol", "name": "GSmartControl", "description": "Disk health monitor", "category": "Utils"},
    {"id": "gwenview", "name": "Gwenview", "description": "KDE image viewer", "category": "Utils"},
    {"id": "hardinfo", "name": "HardInfo", "description": "System information", "category": "Utils"},
    {"id": "joystick", "name": "joystick", "description": "Joystick utilities", "category": "Utils"},
    {"id": "jstest-gtk", "name": "jstest-gtk", "description": "Joystick tester GUI", "category": "Utils"},
    {"id": "kdeconnect", "name": "KDE Connect", "description": "Phone-desktop integration", "category": "Utils"},
    {"id": "kdiff3", "name": "KDiff3", "description": "Diff and merge tool", "category": "Utils"},
    {"id": "meld", "name": "Meld", "description": "Visual diff and merge", "category": "Utils"},
    {"id": "okular", "name": "Okular", "description": "Document viewer", "category": "Utils"},
    {"id": "remmina", "name": "Remmina", "description": "Remote desktop client", "category": "Utils"},
    {"id": "thunderbird", "name": "Thunderbird", "description": "Email client", "category": "Utils"},
    {"id": "wireshark", "name": "Wireshark", "description": "Network packet analyzer", "category": "Utils"},

    # Video
    {"id": "shotcut", "name": "Shotcut", "description": "Video editor", "category": "Video"},
    {"id": "vlc", "name": "VLC", "description": "Media player", "category": "Video"},

    # Virtualization
    {"id": "flatpak", "name": "Flatpak", "description": "Application sandboxing", "category": "Virtualization"},
    {"id": "guestfish", "name": "guestfish", "description": "VM disk shell", "category": "Virtualization"},
    {"id": "guestfs-tools", "name": "guestfs-tools", "description": "VM disk utilities", "category": "Virtualization"},
    {"id": "ovmf", "name": "OVMF", "description": "UEFI firmware for VMs", "category": "Virtualization"},
    {"id": "qemu-kvm", "name": "QEMU/KVM", "description": "Hardware virtualization", "category": "Virtualization"},
    {"id": "qemu-utils", "name": "QEMU Utils", "description": "QEMU disk utilities", "category": "Virtualization"},
    {"id": "virt-manager", "name": "Virt-Manager", "description": "VM management GUI", "category": "Virtualization"},
    {"id": "virtualbox-guest-additions-iso", "name": "VBox Guest Additions ISO", "description": "VirtualBox guest tools", "category": "Virtualization"},
    {"id": "virtualbox-guest-utils", "name": "VBox Guest Utils", "description": "VirtualBox guest utilities", "category": "Virtualization"},
    {"id": "virtualbox-guest-x11", "name": "VBox Guest X11", "description": "VirtualBox X11 drivers", "category": "Virtualization"},
    {"id": "virtualbox", "name": "VirtualBox", "description": "Desktop virtualization", "category": "Virtualization"},
    {"id": "xdg-desktop-portal", "name": "XDG Desktop Portal", "description": "Sandboxed app integration", "category": "Virtualization"},

    # Web
    {"id": "apache2", "name": "Apache", "description": "Web server", "category": "Web"},
    {"id": "firefox", "name": "Firefox", "description": "Web browser", "category": "Web"},
    {"id": "uget", "name": "uGet", "description": "Download manager", "category": "Web"},

    # X11
    {"id": "wmctrl", "name": "wmctrl", "description": "Window manager control", "category": "X11"},
]

###########################################################
# AptGet - Remote Ubuntu
###########################################################
aptget[constants.EnvironmentType.REMOTE_UBUNTU] += [

    # Admin
    {"id": "7zip", "name": "7-Zip", "description": "High compression file archiver", "category": "Admin"},
    {"id": "apt-file", "name": "apt-file", "description": "Search for files in apt packages", "category": "Admin"},
    {"id": "unzip", "name": "unzip", "description": "Extract ZIP archives", "category": "Admin"},
    {"id": "zip", "name": "zip", "description": "Create ZIP archives", "category": "Admin"},

    # Devel
    {"id": "default-jdk", "name": "OpenJDK", "description": "Java Development Kit", "category": "Devel"},
    {"id": "git", "name": "Git", "description": "Version control system", "category": "Devel"},
    {"id": "jq", "name": "jq", "description": "JSON processor", "category": "Devel"},

    # Server
    {"id": "certbot", "name": "Certbot", "description": "Let's Encrypt client", "category": "Server"},
    {"id": "nginx", "name": "Nginx", "description": "Web server", "category": "Server"},
    {"id": "nginx-common", "name": "Nginx Common", "description": "Nginx common files", "category": "Server"},
    {"id": "python3-certbot-nginx", "name": "Certbot Nginx", "description": "Nginx plugin for Certbot", "category": "Server"},

    # Net
    {"id": "curl", "name": "cURL", "description": "URL transfer tool", "category": "Net"},
    {"id": "wget", "name": "wget", "description": "File downloader", "category": "Net"},

    # Virtualization
    {"id": "docker-buildx", "name": "Docker Buildx", "description": "Docker build extensions", "category": "Virtualization"},
    {"id": "docker-compose", "name": "Docker Compose", "description": "Multi-container orchestration", "category": "Virtualization"},
    {"id": "docker-compose-v2", "name": "Docker Compose v2", "description": "Docker Compose plugin", "category": "Virtualization"},
    {"id": "docker.io", "name": "Docker", "description": "Container runtime", "category": "Virtualization"},
    {"id": "flatpak", "name": "Flatpak", "description": "Application sandboxing", "category": "Virtualization"},
]
