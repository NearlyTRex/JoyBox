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

# Hostnames only, so a name cannot walk out of /etc/letsencrypt/live
is_valid_domain() {
    [[ "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$ ]]
}

# A staged file has to be a regular file belonging to whoever ran sudo, so
# this cannot be used to copy out a file only root can read
is_callers_file() {
    local path="$1"
    [ -f "$path" ] && [ ! -L "$path" ] && [ "$(stat -c %u "$path")" = "${SUDO_UID:-0}" ]
}

install_pair() {
    if [ "$#" -ne 3 ]; then
        echo "Usage: install_pair <domain> <staged_fullchain> <staged_privkey>"
        exit 1
    fi

    local DOMAIN="$1"
    local FULLCHAIN="$2"
    local PRIVKEY="$3"
    local CERT_DIR="/etc/letsencrypt/live/$DOMAIN"

    if ! is_valid_domain "$DOMAIN"; then
        echo "Error: '$DOMAIN' is not a domain name"
        exit 1
    fi
    for FILE in "$FULLCHAIN" "$PRIVKEY"; do
        if ! is_callers_file "$FILE"; then
            echo "Error: $FILE is not a regular file owned by the caller"
            exit 1
        fi
    done
    if ! openssl x509 -in "$FULLCHAIN" -noout; then
        echo "Error: $FULLCHAIN is not a certificate"
        exit 1
    fi
    if ! openssl pkey -in "$PRIVKEY" -noout; then
        echo "Error: $PRIVKEY is not a private key"
        exit 1
    fi

    mkdir -p "$CERT_DIR"
    install -m 644 -o root -g root "$FULLCHAIN" "$CERT_DIR/fullchain.pem"
    install -m 600 -o root -g root "$PRIVKEY" "$CERT_DIR/privkey.pem"
    echo "Installed certificate to $CERT_DIR"
}

selfsign_cert() {
    if [ "$#" -lt 1 ]; then
        echo "Usage: selfsign <domain> [other_name ...]"
        exit 1
    fi

    local DOMAIN="$1"
    local CERT_DIR="/etc/letsencrypt/live/$DOMAIN"
    local SANS=""
    for NAME in "$@"; do
        if ! is_valid_domain "$NAME"; then
            echo "Error: '$NAME' is not a domain name"
            exit 1
        fi
        SANS="${SANS:+$SANS,}DNS:$NAME"
    done

    mkdir -p "$CERT_DIR"
    openssl req -x509 -newkey rsa:2048 -nodes \
        -days 825 \
        -subj "/CN=$DOMAIN" \
        -addext "subjectAltName=$SANS" \
        -keyout "$CERT_DIR/privkey.pem" \
        -out "$CERT_DIR/fullchain.pem"
    chmod 644 "$CERT_DIR/fullchain.pem"
    chmod 600 "$CERT_DIR/privkey.pem"
    echo "Generated a self-signed certificate in $CERT_DIR"
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
        echo "Usage: export_keystore <domain> <destination_path> <password> <alias> [format] [permissions] [owner]"
        echo "  format: p12 (default) or jks"
        echo "  permissions: file permissions (default: 600)"
        echo "  owner: file owner in format user:group (default: current user)"
        exit 1
    fi

    local DOMAIN="$1"
    local DEST_PATH="$2"
    local PASSWORD="$3"
    local ALIAS="$4"
    local FORMAT="${5:-p12}"
    local PERMISSIONS="${6:-600}"
    local OWNER="${7:-}"
    local CERT_DIR="/etc/letsencrypt/live/$DOMAIN"
    local ARCHIVE_DIR="/etc/letsencrypt/archive/$DOMAIN"

    echo "Exporting certificate for domain: $DOMAIN"
    echo "Format: $FORMAT"
    echo "Alias: $ALIAS"
    echo "Destination: $DEST_PATH"
    echo "Permissions: $PERMISSIONS"
    if [ -n "$OWNER" ]; then
        echo "Owner: $OWNER"
    else
        echo "Owner: (unchanged)"
    fi

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

    echo "Setting permissions to $PERMISSIONS..."
    chmod "$PERMISSIONS" "$DEST_PATH"

    if [ -n "$OWNER" ]; then
        echo "Setting owner to $OWNER..."
        chown "$OWNER" "$DEST_PATH"
    fi

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

    echo "File permissions: $(ls -la "$DEST_PATH" | awk '{print $1, $3, $4}')"
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
    echo "  $0 install_pair <domain> <staged_fullchain> <staged_privkey>"
    echo "  $0 selfsign <domain> [other_name ...]"
    echo "  $0 copy_certs <domain> <destination_dir>"
    echo "  $0 export_keystore <domain> <dest_path> <password> <alias> [format] [permissions] [owner]"
    echo "  $0 list"
    echo "  $0 check <domain>"
    echo ""
    echo "Examples:"
    echo "  $0 copy_certs squaredbinary.com /home/user/apps/myapp/certs"
    echo "  $0 export_keystore squaredbinary.com /opt/app/keystore.p12 mypassword squaredbinary.com p12"
    echo "  $0 export_keystore squaredbinary.com /opt/app/keystore.jks mypassword myapp jks 600 100000:100000"
    echo "  $0 export_keystore squaredbinary.com /opt/app/keystore.p12 mypassword myapp p12 644 www-data:www-data"
    echo "  $0 list"
    echo "  $0 check squaredbinary.com"
    echo ""
    echo "Keystore formats:"
    echo "  p12  - PKCS12 format (default, widely supported)"
    echo "  jks  - Java KeyStore format (requires keytool/Java JDK)"
    echo ""
    echo "Permission examples:"
    echo "  600  - Read/write for owner only (default)"
    echo "  644  - Read/write for owner, read for group and others"
    echo "  640  - Read/write for owner, read for group"
    echo ""
    echo "Owner examples:"
    echo "  100000:100000  - Docker namespace remapping"
    echo "  www-data:www-data  - Web server user"
    echo "  myuser:mygroup  - Custom user and group"
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
    install_pair)
        if [ $# -ne 4 ]; then
            echo "Error: install_pair requires domain, certificate and key"
            print_usage
        fi
        install_pair "$2" "$3" "$4"
        ;;
    selfsign)
        if [ $# -lt 2 ]; then
            echo "Error: selfsign requires at least one domain"
            print_usage
        fi
        selfsign_cert "${@:2}"
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
        export_keystore "$2" "$3" "$4" "$5" "${6:-p12}" "${7:-600}" "${8:-}"
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
