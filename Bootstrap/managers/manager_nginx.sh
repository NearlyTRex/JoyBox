#!/bin/bash

set -euo pipefail

NGINX_SITES_AVAILABLE="/etc/nginx/sites-available"
NGINX_SITES_ENABLED="/etc/nginx/sites-enabled"
NGINX_STREAMS_AVAILABLE="/etc/nginx/streams-available"
NGINX_STREAMS_ENABLED="/etc/nginx/streams-enabled"
HTML_DIR="/var/www/html"
ACME_CHALLENGE_DIR="/var/www/html/.well-known/acme-challenge"

print_usage() {
    echo "Usage:"
    echo "  $0 install_conf <absolute_path_to_conf>"
    echo "  $0 link_conf <conf_filename>"
    echo "  $0 remove_conf <conf_filename>"
    echo "  $0 install_stream_conf <absolute_path_to_conf>"
    echo "  $0 link_stream_conf <conf_filename>"
    echo "  $0 remove_stream_conf <conf_filename>"
    echo "  $0 open_port <port_number>"
    echo "  $0 close_port <port_number>"
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

check_port_number() {
    local port="$1"
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        echo "Error: Invalid port number '$port'. Must be between 1 and 65535."
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

    install_stream_conf)
        sanitize_path "$2"
        check_path "$2"

        mkdir -p "$NGINX_STREAMS_AVAILABLE"
        mkdir -p "$NGINX_STREAMS_ENABLED"

        cp -R "$2" "$NGINX_STREAMS_AVAILABLE/"
        echo "Stream configuration file installed in $NGINX_STREAMS_AVAILABLE."
        ;;

    link_stream_conf)
        check_directory_traversal "$2"

        local_path="$NGINX_STREAMS_AVAILABLE/$2"
        if [ ! -e "$local_path" ]; then
            echo "Error: Stream configuration file '$2' does not exist in $NGINX_STREAMS_AVAILABLE."
            exit 1
        fi

        mkdir -p "$NGINX_STREAMS_ENABLED"
        ln -sf "$local_path" "$NGINX_STREAMS_ENABLED/$2"
        echo "Stream configuration file linked from streams-available to streams-enabled."
        ;;

    remove_stream_conf)
        check_directory_traversal "$2"

        local_path="$NGINX_STREAMS_ENABLED/$2"
        [ -e "$local_path" ] && rm -f "$local_path"

        local_path="$NGINX_STREAMS_AVAILABLE/$2"
        [ -e "$local_path" ] && rm -f "$local_path"

        echo "Stream configuration files removed from streams-available and streams-enabled."
        ;;

    open_port)
        if [ $# -ne 2 ]; then
            echo "Usage: $0 open_port <port_number>"
            exit 1
        fi

        local port="$2"
        check_port_number "$port"

        echo "Opening firewall port $port..."
        if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
            if ufw allow "$port"; then
                echo "Port $port opened successfully."
            else
                echo "Error: Failed to open port $port."
                exit 1
            fi
        else
            echo "UFW is not active or not installed. Skipping firewall configuration."
        fi
        ;;

    close_port)
        if [ $# -ne 2 ]; then
            echo "Usage: $0 close_port <port_number>"
            exit 1
        fi

        local port="$2"
        check_port_number "$port"

        echo "Closing firewall port $port..."
        if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
            if ufw delete allow "$port"; then
                echo "Port $port closed successfully."
            else
                echo "Warning: Failed to close port $port. Rule may not exist."
            fi
        else
            echo "UFW is not active or not installed. Skipping firewall configuration."
        fi
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
