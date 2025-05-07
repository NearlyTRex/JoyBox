#!/bin/bash

# Check if the script is being run with bash
if [ -z "$BASH_VERSION" ]; then
    echo "Error: This script must be run with bash"
    exit 1
fi

# Define variables
SUDOERS_FILE="/etc/sudoers.d/server-setup"
USERNAME="ubuntu"
NGINX_SCRIPT_URL="https://raw.githubusercontent.com/NearlyTRex/JoyBox/main/Bootstrap/managers/manager_nginx.sh"
CERTBOT_SCRIPT_URL="https://raw.githubusercontent.com/NearlyTRex/JoyBox/main/Bootstrap/managers/manager_certbot.sh"
AZURACAST_SCRIPT_URL="https://raw.githubusercontent.com/NearlyTRex/JoyBox/main/Bootstrap/managers/manager_azuracast.sh"

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

# Define apt packages
APT_PACKAGES=(
    7zip
    apache2-utils
    apache2
    apt-file
    certbot
    curl
    docker-compose
    docker.io
    flatpak
    git
    nginx-common
    nginx
    python3-certbot-nginx
    unzip
    wget
    zip
)

# Create sudoers file
echo "Setting up sudoers config for user: $USERNAME"
TEMP_FILE=$(mktemp)
{
    echo "Cmnd_Alias APT_MANAGE = \\"
    echo "    /usr/bin/apt-get update, \\"
    echo "    /usr/bin/apt-get autoremove -y, \\"
    last_index=$((${#APT_PACKAGES[@]} - 1))
    for i in "${!APT_PACKAGES[@]}"; do
        pkg="${APT_PACKAGES[$i]}"
        if [[ "$i" -eq "$last_index" ]]; then
            echo "    /usr/bin/apt-get install -y $pkg, \\"
            echo "    /usr/bin/apt-get remove -y $pkg"
        else
            echo "    /usr/bin/apt-get install -y $pkg, \\"
            echo "    /usr/bin/apt-get remove -y $pkg, \\"
        fi
    done
    echo ""
    echo "Cmnd_Alias MANAGER_NGINX = /usr/local/bin/manager_nginx.sh"
    echo "Cmnd_Alias MANAGER_CERTBOT = /usr/local/bin/manager_certbot.sh"
    echo "Cmnd_Alias MANAGER_AZURACAST = /usr/local/bin/manager_azuracast.sh"
    echo "$USERNAME ALL=(ALL) NOPASSWD: APT_MANAGE, MANAGER_NGINX, MANAGER_CERTBOT, MANAGER_AZURACAST"
} > "$TEMP_FILE"

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

# Ensure /usr/local/bin exists
mkdir -p /usr/local/bin

# Download and install nginx manager script
echo "Downloading manager_nginx.sh..."
if curl -fsSL -o /usr/local/bin/manager_nginx.sh "$NGINX_SCRIPT_URL"; then
    chmod +x /usr/local/bin/manager_nginx.sh
    echo "manager_nginx.sh installed to /usr/local/bin/"
else
    echo "Error: Failed to download manager_nginx.sh"
    exit 1
fi

# Download and install certbot manager script
echo "Downloading manager_certbot.sh..."
if curl -fsSL -o /usr/local/bin/manager_certbot.sh "$CERTBOT_SCRIPT_URL"; then
    chmod +x /usr/local/bin/manager_certbot.sh
    echo "manager_certbot.sh installed to /usr/local/bin/"
else
    echo "Error: Failed to download manager_certbot.sh"
    exit 1
fi

# Download and install azuracast manager script
echo "Downloading manager_azuracast.sh..."
if curl -fsSL -o /usr/local/bin/manager_azuracast.sh "$AZURACAST_SCRIPT_URL"; then
    chmod +x /usr/local/bin/manager_azuracast.sh
    echo "manager_azuracast.sh installed to /usr/local/bin/"
else
    echo "Error: Failed to download manager_azuracast.sh"
    exit 1
fi
