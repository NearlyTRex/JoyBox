#!/bin/bash

set -euo pipefail

register_cert() {
    if [ "$#" -lt 2 ]; then
        echo "Usage: register_cert <contact_email> <domain1> [domain2 ... domainN]"
        exit 1
    fi

    EMAIL="$1"
    shift
    DOMAINS=("$@")

    echo "Registering new SSL certificate for the following domains: ${DOMAINS[*]}..."
    CMD=("certbot" "certonly" "--nginx" "--non-interactive" "--expand" "--agree-tos" "--email" "$EMAIL")
    for DOMAIN in "${DOMAINS[@]}"; do
        CMD+=("-d" "$DOMAIN")
    done
    "${CMD[@]}"
}

renew_certs() {
    echo "Renewing all SSL certificates..."
    certbot renew --non-interactive --quiet
}

copy_certs() {
    if [ "$#" -ne 2 ]; then
        echo "Usage: copy_certs <domain> <destination_directory>"
        exit 1
    fi

    local DOMAIN="$1"
    local DEST_DIR="$2"
    local CERT_DIR="/etc/letsencrypt/live/$DOMAIN"
    local ARCHIVE_DIR="/etc/letsencrypt/archive/$DOMAIN"

    echo "Copying certificates for domain: $DOMAIN"
    echo "Destination: $DEST_DIR"

    mkdir -p "$DEST_DIR"
    if [ ! -d "$CERT_DIR" ]; then
        echo "Error: Certificate directory $CERT_DIR does not exist"
        echo "Available domains:"
        ls -1 /etc/letsencrypt/live/ 2>/dev/null | grep -v README || echo "  No certificates found"
        exit 1
    fi

    if [ -f "$CERT_DIR/fullchain.pem" ] && [ -f "$CERT_DIR/privkey.pem" ]; then
        echo "Copying certificates from live directory..."
        cp "$CERT_DIR/fullchain.pem" "$DEST_DIR/"
        cp "$CERT_DIR/privkey.pem" "$DEST_DIR/"
        echo "Certificates copied successfully"
    else
        echo "Live directory not accessible, copying from archive..."
        if [ ! -d "$ARCHIVE_DIR" ]; then
            echo "Error: Archive directory $ARCHIVE_DIR does not exist"
            exit 1
        fi

        local LATEST_FULLCHAIN=$(find "$ARCHIVE_DIR" -name "fullchain*.pem" | sort -V | tail -1)
        local LATEST_PRIVKEY=$(find "$ARCHIVE_DIR" -name "privkey*.pem" | sort -V | tail -1)
        if [ -z "$LATEST_FULLCHAIN" ] || [ -z "$LATEST_PRIVKEY" ]; then
            echo "Error: Could not find certificate files in $ARCHIVE_DIR"
            exit 1
        fi

        echo "Found latest fullchain: $LATEST_FULLCHAIN"
        echo "Found latest privkey: $LATEST_PRIVKEY"

        cp "$LATEST_FULLCHAIN" "$DEST_DIR/fullchain.pem"
        cp "$LATEST_PRIVKEY" "$DEST_DIR/privkey.pem"
        echo "Certificates copied successfully from archive"
    fi

    chmod 644 "$DEST_DIR/fullchain.pem"
    chmod 600 "$DEST_DIR/privkey.pem"

    echo "Certificate files in $DEST_DIR:"
    ls -la "$DEST_DIR/"*.pem

    echo "Certificate details:"
    openssl x509 -in "$DEST_DIR/fullchain.pem" -noout -subject -issuer -dates
}

list_certs() {
    echo "Available Let's Encrypt certificates:"
    if [ -d "/etc/letsencrypt/live" ]; then
        for cert_dir in /etc/letsencrypt/live/*/; do
            if [ -d "$cert_dir" ] && [ "$(basename "$cert_dir")" != "README" ]; then
                local domain=$(basename "$cert_dir")
                echo "  Domain: $domain"
                if [ -f "$cert_dir/cert.pem" ]; then
                    local expiry=$(openssl x509 -in "$cert_dir/cert.pem" -noout -enddate | cut -d= -f2)
                    echo "    Expires: $expiry"
                fi
            fi
        done
    else
        echo "  No certificates found"
    fi
}

check_cert() {
    if [ "$#" -ne 1 ]; then
        echo "Usage: check_cert <domain>"
        exit 1
    fi

    local DOMAIN="$1"
    local CERT_DIR="/etc/letsencrypt/live/$DOMAIN"

    if [ ! -d "$CERT_DIR" ]; then
        echo "Certificate for domain '$DOMAIN' does not exist"
        exit 1
    fi

    echo "Certificate information for $DOMAIN:"
    if [ -f "$CERT_DIR/cert.pem" ]; then
        openssl x509 -in "$CERT_DIR/cert.pem" -noout -text | grep -E "(Subject:|Issuer:|Not Before|Not After)"
    else
        echo "Certificate file not found"
        exit 1
    fi
}

print_usage() {
    echo "Usage:"
    echo "  $0 register <email> <domain1> [domain2 ...]   - Register new certificate"
    echo "  $0 renew                                      - Renew all certificates"
    echo "  $0 copy_certs <domain> <destination_dir>      - Copy certificates to directory"
    echo "  $0 list                                       - List available certificates"
    echo "  $0 check <domain>                             - Check certificate details"
    echo ""
    echo "Examples:"
    echo "  $0 copy_certs squaredbinary.com /home/user/apps/ghidra_server/certs"
    echo "  $0 list"
    echo "  $0 check squaredbinary.com"
    exit 1
}

if [ $# -lt 1 ]; then
    print_usage
fi

case "$1" in
    register)
        if [ $# -lt 3 ]; then
            echo "Error: register requires email and at least one domain"
            print_usage
        fi
        register_cert "$2" "${@:3}"
        ;;
    renew)
        renew_certs
        ;;
    copy_certs)
        if [ $# -ne 3 ]; then
            echo "Error: copy_certs requires domain and destination directory"
            print_usage
        fi
        copy_certs "$2" "$3"
        ;;
    list)
        list_certs
        ;;
    check)
        if [ $# -ne 2 ]; then
            echo "Error: check requires domain name"
            print_usage
        fi
        check_cert "$2"
        ;;
    *)
        echo "Error: Invalid operation '$1'."
        print_usage
        ;;
esac
