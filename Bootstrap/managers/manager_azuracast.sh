#!/bin/bash

install_azuracast() {

    echo "Making install directory"
    mkdir -p /var/azuracast
    cd /var/azuracast || { echo "Failed to change directory to /var/azuracast"; exit 1; }

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

    if [ ! -d "/var/azuracast" ]; then
        echo "AzuraCast directory not found at /var/azuracast. Nothing to uninstall."
        exit 1
    fi

    cd /var/azuracast || {
        echo "Failed to change directory to /var/azuracast"
        exit 1
    }

    if [ -f "./docker.sh" ]; then
        echo "Running uninstall"
        ./docker.sh uninstall
    else
        echo "docker.sh not found. Please ensure AzuraCast was installed properly."
        exit 1
    fi

    echo "Cleaning up install directory"
    rm -rf /var/azuracast
}

print_usage() {
    echo "Usage:"
    echo "  $0 install          Install AzuraCast"
    echo "  $0 uninstall        Uninstall AzuraCast"
    exit 1
}

if [ $# -ne 1 ]; then
    print_usage
fi

case "$1" in
    install)
        install_azuracast
        ;;
    uninstall)
        uninstall_azuracast
        ;;
    *)
        echo "Error: Invalid operation '$1'."
        print_usage
        ;;
esac
