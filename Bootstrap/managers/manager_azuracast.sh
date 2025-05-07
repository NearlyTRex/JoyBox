#!/bin/bash

install_azuracast() {

    AZURACAST_DIR="$1"
    if [ -z "$AZURACAST_DIR" ]; then
        echo "Error: Missing directory argument for install."
        echo "Usage: $0 install <install_dir>"
        exit 1
    fi

    echo "Making install directory"
    mkdir -p "$AZURACAST_DIR"
    cd "$AZURACAST_DIR" || { echo "Failed to change directory to $AZURACAST_DIR"; exit 1; }

    echo "Downloading installation script"
    curl -fsSL https://raw.githubusercontent.com/AzuraCast/AzuraCast/main/docker.sh -o docker.sh || {
        echo "Failed to download docker.sh"
        exit 1
    }

    echo "Running install"
    chmod a+x docker.sh
    yes '' | ./docker.sh install
}

uninstall_azuracast() {

    AZURACAST_DIR="$1"
    if [ -z "$AZURACAST_DIR" ]; then
        echo "Error: Missing directory argument for uninstall."
        echo "Usage: $0 uninstall <install_dir>"
        exit 1
    fi

    if [ ! -d "$AZURACAST_DIR" ]; then
        echo "Directory $AZURACAST_DIR does not exist. Nothing to uninstall."
        exit 1
    fi

    cd "$AZURACAST_DIR" || {
        echo "Failed to change directory to $AZURACAST_DIR"
        exit 1
    }

    if [ -f "./docker.sh" ]; then
        echo "Running uninstall"
        ./docker.sh uninstall
    else
        echo "docker.sh not found in $AZURACAST_DIR. Cannot proceed with uninstall."
        exit 1
    fi

    echo "Cleaning up install directory"
    rm -rf "$AZURACAST_DIR"
}

print_usage() {
    echo "Usage:"
    echo "  $0 install <install_dir>     Install AzuraCast into specified directory"
    echo "  $0 uninstall <install_dir>   Uninstall AzuraCast from specified directory"
    exit 1
}

if [ $# -ne 2 ]; then
    print_usage
fi

COMMAND="$1"
TARGET_DIR="$2"

case "$COMMAND" in
    install)
        install_azuracast "$TARGET_DIR"
        ;;
    uninstall)
        uninstall_azuracast "$TARGET_DIR"
        ;;
    *)
        echo "Error: Invalid operation '$COMMAND'."
        print_usage
        ;;
esac
