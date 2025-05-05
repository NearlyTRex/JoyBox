#!/bin/bash

# Check if the script is being run with bash
if [ -z "$BASH_VERSION" ]; then
    echo "Error: This script must be run with bash"
    exit 1
fi

# Define variables
SUDOERS_FILE="/etc/sudoers.d/server-setup"
USERNAME="ubuntu"

# Only run as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run this script as root (e.g., with sudo)"
    exit 1
fi

# Take username as an argument
if [ -n "$1" ]; then
    USERNAME="$1"
fi

# Check that user exists
if ! id "$USERNAME" &>/dev/null; then
    echo "Error: User '$USERNAME' does not exist."
    exit 1
fi

# Create sudoers file
echo "Setting up sudoers config for user: $USERNAME"
TEMP_FILE=$(mktemp)
cat > "$TEMP_FILE" <<EOF
Cmnd_Alias NGINX_CONF_MGMT = \\
    /bin/mv /tmp/*.conf /etc/nginx/sites-available/, \\
    /bin/ln -sf /etc/nginx/sites-available/*.conf /etc/nginx/sites-enabled/, \\
    /bin/rm -f /etc/nginx/sites-available/*.conf, \\
    /bin/rm -f /etc/nginx/sites-enabled/*.conf, \\
    /bin/systemctl reload nginx

Cmnd_Alias APT_MANAGE = \\
    /usr/bin/apt-get update, \\
    /usr/bin/apt-get install -y apache2-utils, \\
    /usr/bin/apt-get install -y apache2, \\
    /usr/bin/apt-get install -y certbot, \\
    /usr/bin/apt-get install -y curl, \\
    /usr/bin/apt-get install -y docker-compose, \\
    /usr/bin/apt-get install -y docker.io, \\
    /usr/bin/apt-get install -y git, \\
    /usr/bin/apt-get install -y nginx, \\
    /usr/bin/apt-get install -y nginx-common, \\
    /usr/bin/apt-get install -y python3-certbot-nginx, \\
    /usr/bin/apt-get install -y unzip, \\
    /usr/bin/apt-get install -y wget, \\
    /usr/bin/apt-get remove -y apache2-utils, \\
    /usr/bin/apt-get remove -y apache2, \\
    /usr/bin/apt-get remove -y certbot, \\
    /usr/bin/apt-get remove -y curl, \\
    /usr/bin/apt-get remove -y docker-compose, \\
    /usr/bin/apt-get remove -y docker.io, \\
    /usr/bin/apt-get remove -y git, \\
    /usr/bin/apt-get remove -y nginx, \\
    /usr/bin/apt-get remove -y nginx-common, \\
    /usr/bin/apt-get remove -y python3-certbot-nginx, \\
    /usr/bin/apt-get remove -y unzip, \\
    /usr/bin/apt-get remove -y wget, \\
    /usr/bin/apt-get autoremove -y

$USERNAME ALL=(ALL) NOPASSWD: NGINX_CONF_MGMT, APT_MANAGE
EOF

# Validate and install sudoers config
if visudo -c -f "$TEMP_FILE"; then
    mv "$TEMP_FILE" "$SUDOERS_FILE"
    chmod 0440 "$SUDOERS_FILE"
    echo "Sudoers configuration installed at $SUDOERS_FILE"
else
    echo "Error: Invalid sudoers syntax. Aborting."
    rm -f "$TEMP_FILE"
    exit 1
fi

# Ensure the docker group exists
if ! getent group docker > /dev/null 2>&1; then
    echo "Docker group does not exist. Creating the docker group."
    groupadd docker
fi

# Add user to docker group
if groups "$USERNAME" | grep -qw docker; then
    echo "User '$USERNAME' is already in the 'docker' group."
else
    usermod -aG docker "$USERNAME"
    echo "Added '$USERNAME' to the 'docker' group. You may need to re-login to apply group changes."
fi
