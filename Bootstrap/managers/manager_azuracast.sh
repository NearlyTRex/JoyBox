#!/bin/bash

install_azuracast() {
    AZURACAST_DIR="$1"
    ENV_FILE="$2"
    COMPOSE_FILE="$3"

    if [ -z "$AZURACAST_DIR" ]; then
        echo "Error: Missing directory argument for install."
        echo "Usage: $0 install <install_dir> [--env <env_file>] [--compose <docker_compose_file>]"
        exit 1
    fi

    echo "Creating install directory at $AZURACAST_DIR"
    mkdir -p "$AZURACAST_DIR"
    cd "$AZURACAST_DIR" || { echo "Failed to change directory to $AZURACAST_DIR"; exit 1; }

    if [ -n "$ENV_FILE" ]; then
        echo "Copying env file from $ENV_FILE"
        cp "$ENV_FILE" .env || { echo "Failed to copy env file"; exit 1; }
    fi

    if [ -n "$COMPOSE_FILE" ]; then
        echo "Copying Docker Compose file from $COMPOSE_FILE"
        cp "$COMPOSE_FILE" docker-compose.yml || { echo "Failed to copy docker compose file"; exit 1; }
    fi

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
    echo "  $0 install <install_dir> [--env <env_file>] [--compose <docker_compose_file>]"
    echo "  $0 uninstall <install_dir>"
    exit 1
}

COMMAND="$1"
shift

if [ "$COMMAND" == "install" ]; then
    INSTALL_DIR=""
    ENV_FILE=""
    COMPOSE_FILE=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --env)
                ENV_FILE="$2"
                shift 2
                ;;
            --compose)
                COMPOSE_FILE="$2"
                shift 2
                ;;
            *)
                if [ -z "$INSTALL_DIR" ]; then
                    INSTALL_DIR="$1"
                    shift
                else
                    echo "Unknown argument: $1"
                    print_usage
                fi
                ;;
        esac
    done

    install_azuracast "$INSTALL_DIR" "$ENV_FILE" "$COMPOSE_FILE"

elif [ "$COMMAND" == "uninstall" ]; then
    if [ $# -ne 1 ]; then
        print_usage
    fi
    uninstall_azuracast "$1"
else
    echo "Error: Invalid operation '$COMMAND'."
    print_usage
fi
