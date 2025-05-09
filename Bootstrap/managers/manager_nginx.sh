#!/bin/bash

NGINX_SITES_AVAILABLE="/etc/nginx/sites-available"
NGINX_SITES_ENABLED="/etc/nginx/sites-enabled"
HTML_DIR="/var/www/html"
ACME_CHALLENGE_DIR="/var/www/html/.well-known/acme-challenge"
AUTHELIA_CONF_DIR="/etc/nginx/authelia"

print_usage() {
    echo "Usage:"
    echo "  $0 install_conf <absolute_path_to_conf>"
    echo "  $0 link_conf <conf_filename>"
    echo "  $0 remove_conf <conf_filename>"
    echo "  $0 install_authelia_conf <absolute_path_to_conf>"
    echo "  $0 remove_authelia_conf <conf_filename>"
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

check_directory_traversal() {
    local filename="$1"
    if [[ "$filename" == *".."* || "$filename" == */* ]]; then
        echo "Error: Directory traversal or path separators are not allowed in filename."
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
        check_directory_traversal "$2"

        local_path="$NGINX_SITES_AVAILABLE/$2"
        if [ ! -e "$local_path" ]; then
            echo "Error: Configuration file '$2' does not exist in $NGINX_SITES_AVAILABLE."
            exit 1
        fi

        ln -sf "$local_path" "$NGINX_SITES_ENABLED/$2"
        echo "Configuration file linked from sites-available to sites-enabled."
        ;;

    remove_conf)
        check_directory_traversal "$2"

        local_path="$NGINX_SITES_ENABLED/$2"
        [ -e "$local_path" ] && rm -f "$local_path"

        local_path="$NGINX_SITES_AVAILABLE/$2"
        [ -e "$local_path" ] && rm -f "$local_path"

        echo "Configuration files removed from sites-available and sites-enabled."
        ;;

    install_authelia_conf)
        sanitize_path "$2"
        check_path "$2"

        mkdir -p "$AUTHELIA_CONF_DIR"
        cp -R "$2" "$AUTHELIA_CONF_DIR/"
        echo "Authelia configuration file installed in $AUTHELIA_CONF_DIR."
        ;;

    remove_authelia_conf)
        check_directory_traversal "$2"

        local_path="$AUTHELIA_CONF_DIR/$2"
        [ -e "$local_path" ] && rm -f "$local_path"

        echo "Configuration files removed from $AUTHELIA_CONF_DIR."
        ;;

    copy_html)
        sanitize_path "$2"
        check_path "$2"

        mkdir -p "$HTML_DIR" "$ACME_CHALLENGE_DIR"
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
