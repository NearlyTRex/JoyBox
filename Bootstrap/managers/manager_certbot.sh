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

export_keystore() {
    if [ "$#" -lt 4 ]; then
        echo "Usage: export_keystore <domain> <destination_path> <password> <alias> [format]"
        echo "  format: p12 (default) or jks"
        exit 1
    fi

    local DOMAIN="$1"
    local DEST_PATH="$2"
    local PASSWORD="$3"
    local ALIAS="$4"
    local FORMAT="${5:-p12}"
    local CERT_DIR="/etc/letsencrypt/live/$DOMAIN"
    local ARCHIVE_DIR="/etc/letsencrypt/archive/$DOMAIN"

    echo "Exporting certificate for domain: $DOMAIN"
    echo "Format: $FORMAT"
    echo "Alias: $ALIAS"
    echo "Destination: $DEST_PATH"

    if [ ! -d "$CERT_DIR" ]; then
        echo "Error: Certificate directory $CERT_DIR does not exist"
        echo "Available domains:"
        ls -1 /etc/letsencrypt/live/ 2>/dev/null | grep -v README || echo "  No certificates found"
        exit 1
    fi

    local FULLCHAIN_FILE=""
    local PRIVKEY_FILE=""
    if [ -f "$CERT_DIR/fullchain.pem" ] && [ -f "$CERT_DIR/privkey.pem" ]; then
        echo "Using certificates from live directory..."
        FULLCHAIN_FILE="$CERT_DIR/fullchain.pem"
        PRIVKEY_FILE="$CERT_DIR/privkey.pem"
    else
        echo "Live directory not accessible, using archive..."
        if [ ! -d "$ARCHIVE_DIR" ]; then
            echo "Error: Archive directory $ARCHIVE_DIR does not exist"
            exit 1
        fi

        FULLCHAIN_FILE=$(find "$ARCHIVE_DIR" -name "fullchain*.pem" | sort -V | tail -1)
        PRIVKEY_FILE=$(find "$ARCHIVE_DIR" -name "privkey*.pem" | sort -V | tail -1)
        if [ -z "$FULLCHAIN_FILE" ] || [ -z "$PRIVKEY_FILE" ]; then
            echo "Error: Could not find certificate files in $ARCHIVE_DIR"
            exit 1
        fi

        echo "Found latest fullchain: $FULLCHAIN_FILE"
        echo "Found latest privkey: $PRIVKEY_FILE"
    fi

    if [ "$FORMAT" != "p12" ] && [ "$FORMAT" != "jks" ]; then
        echo "Error: Invalid format '$FORMAT'. Use 'p12' or 'jks'"
        exit 1
    fi

    local DEST_DIR=$(dirname "$DEST_PATH")
    mkdir -p "$DEST_DIR"

    local TEMP_P12=""
    if [ "$FORMAT" = "p12" ]; then
        echo "Creating PKCS12 keystore..."
        openssl pkcs12 -export \
            -in "$FULLCHAIN_FILE" \
            -inkey "$PRIVKEY_FILE" \
            -out "$DEST_PATH" \
            -name "$ALIAS" \
            -password "pass:$PASSWORD"
    else
        TEMP_P12=$(mktemp --suffix=.p12)
        echo "Creating temporary PKCS12 keystore..."
        openssl pkcs12 -export \
            -in "$FULLCHAIN_FILE" \
            -inkey "$PRIVKEY_FILE" \
            -out "$TEMP_P12" \
            -name "$ALIAS" \
            -password "pass:$PASSWORD"

        echo "Converting to JKS format..."
        if command -v keytool >/dev/null 2>&1; then
            keytool -importkeystore \
                -srckeystore "$TEMP_P12" \
                -srcstoretype PKCS12 \
                -srcstorepass "$PASSWORD" \
                -destkeystore "$DEST_PATH" \
                -deststoretype JKS \
                -deststorepass "$PASSWORD" \
                -destkeypass "$PASSWORD" \
                -noprompt
        else
            echo "Error: keytool not found. Install Java JDK to create JKS keystores."
            rm -f "$TEMP_P12"
            exit 1
        fi
        rm -f "$TEMP_P12"
    fi
    chmod 600 "$DEST_PATH"

    echo "Keystore exported successfully to: $DEST_PATH"
    echo "Keystore details:"
    if [ "$FORMAT" = "p12" ]; then
        openssl pkcs12 -in "$DEST_PATH" -nokeys -noout -info -password "pass:$PASSWORD" 2>/dev/null || \
        echo "  Format: PKCS12"
    else
        if command -v keytool >/dev/null 2>&1; then
            keytool -list -keystore "$DEST_PATH" -storepass "$PASSWORD" -v | head -20
        else
            echo "  Format: JKS (keytool not available for detailed info)"
        fi
    fi

    echo "File size: $(ls -lh "$DEST_PATH" | awk '{print $5}')"
    echo "Remember to keep your keystore password secure!"
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
    echo "  $0 register <email> <domain1> [domain2 ...]"
    echo "  $0 renew"
    echo "  $0 copy_certs <domain> <destination_dir>"
    echo "  $0 export_keystore <domain> <dest_path> <password> <alias> [format]"
    echo "  $0 list"
    echo "  $0 check <domain>"
    echo ""
    echo "Examples:"
    echo "  $0 copy_certs squaredbinary.com /home/user/apps/ghidra_server/certs"
    echo "  $0 export_keystore squaredbinary.com /opt/app/keystore.p12 mypassword squaredbinary.com p12"
    echo "  $0 export_keystore squaredbinary.com /opt/app/keystore.jks mypassword myapp jks"
    echo "  $0 list"
    echo "  $0 check squaredbinary.com"
    echo ""
    echo "Keystore formats:"
    echo "  p12  - PKCS12 format (default, widely supported)"
    echo "  jks  - Java KeyStore format (requires keytool/Java JDK)"
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
    export_keystore)
        if [ $# -lt 5 ]; then
            echo "Error: export_keystore requires domain, destination path, password, and alias"
            print_usage
        fi
        export_keystore "$2" "$3" "$4" "$5" "${6:-p12}"
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
