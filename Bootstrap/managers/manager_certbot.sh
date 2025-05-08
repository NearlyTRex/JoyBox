#!/bin/bash

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

print_usage() {
    echo "Usage:"
    echo "  $0 register <email> <domain1> [domain2 ...]"
    echo "  $0 renew"
    exit 1
}

if [ $# -lt 1 ]; then
    print_usage
fi

case "$1" in
    register)
        register_cert "$2" "${@:3}"
        ;;
    renew)
        renew_certs
        ;;
    *)
        echo "Error: Invalid operation '$1'."
        print_usage
        ;;
esac
