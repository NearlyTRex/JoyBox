#!/bin/bash

NGINX_SITES_AVAILABLE="/etc/nginx/sites-available"
NGINX_SITES_ENABLED="/etc/nginx/sites-enabled"
HTML_DIR="/var/www/html"
ACME_CHALLENGE_DIR="/var/www/html/.well-known/acme-challenge"

print_usage() {
    echo "Usage:"
    echo "  $0 install_conf <absolute_path_to_conf>"
    echo "  $0 link_conf <conf_filename>"
    echo "  $0 remove_conf <conf_filename>"
    echo "  $0 copy_html <absolute_path_to_html_files>"
    echo "  $0 systemctl <reload|restart|status>"
    exit 1
}

check_path() {
    local path=$1
    if [ ! -e "$path" ]; then
        echo "Error: Path $path does not exist."
        exit 1
    fi
}

sanitize_path() {
    local path="$1"
    if [[ "$path" != /* ]]; then
        echo "Error: Path must be absolute or under \$HOME."
        exit 1
    fi

    local abs_path
    abs_path=$(realpath -m "$path")
    if [[ "$abs_path" != "$HOME/"* && "$abs_path" != "$HOME" && "$abs_path" != /* ]]; then
        echo "Error: Path is outside allowed directories."
        exit 1
    fi
}

if [ $# -lt 2 ]; then
    print_usage
fi

case "$1" in
    install_conf)
        sanitize_path "$2"
        check_path "$2"

        cp -R "$2" "$NGINX_SITES_AVAILABLE/"
        echo "Configuration file installed in $NGINX_SITES_AVAILABLE."
        ;;

    link_conf)
        sanitize_path "$2"
        check_path "$2"

        BASENAME=$(basename "$2")
        ln -sf "$NGINX_SITES_AVAILABLE/$BASENAME" "$NGINX_SITES_ENABLED/$BASENAME"
        echo "Configuration file linked from sites-available to sites-enabled."
        ;;

    remove_conf)
        sanitize_path "$2"

        BASENAME=$(basename "$2")
        rm -f "$NGINX_SITES_ENABLED/$BASENAME"
        rm -f "$NGINX_SITES_AVAILABLE/$BASENAME"
        echo "Configuration files removed from sites-available to sites-enabled."
        ;;

    copy_html)
        sanitize_path "$2"
        check_path "$2"

        if [ ! -d "$HTML_DIR" ]; then
            mkdir -p "$HTML_DIR"
            echo "Created directory $HTML_DIR."
        fi

        if [ ! -d "$ACME_CHALLENGE_DIR" ]; then
            mkdir -p "$ACME_CHALLENGE_DIR"
            echo "Created directory $ACME_CHALLENGE_DIR."
        fi

        cp -R "$2" "$HTML_DIR/"
        echo "Files copied to $HTML_DIR."
        ;;

    systemctl)
        case "$2" in
            reload|restart|status|start|stop|enable|disable)
                if ! systemctl "$2" nginx; then
                    echo "Error: Failed to execute systemctl $2 nginx."
                    exit 1
                fi
                echo "Systemd command executed: systemctl $2 nginx."
                ;;
            *)
                echo "Error: Invalid systemctl command."
                print_usage
                ;;
        esac
        ;;

    *)
        echo "Error: Invalid operation '$1'."
        print_usage
        ;;
esac
