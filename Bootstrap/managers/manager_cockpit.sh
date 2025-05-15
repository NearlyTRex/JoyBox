#!/bin/bash

print_usage() {
    echo "Usage:"
    echo "  $0 systemctl <enable|disable>"
    exit 1
}

if [ $# -lt 2 ]; then
    print_usage
fi

case "$1" in
    systemctl)
        case "$2" in
            enable|disable)
                if ! systemctl "$2" --now cockpit.socket; then
                    echo "Error: Failed to execute: systemctl $2 cockpit.socket."
                    exit 1
                fi
                echo "Systemd command executed: systemctl $2 cockpit.socket."
                ;;
            *)
                echo "Error: Invalid systemctl command '$2'."
                print_usage
                ;;
        esac
        ;;
    *)
        echo "Error: Invalid operation '$1'."
        print_usage
        ;;
esac
