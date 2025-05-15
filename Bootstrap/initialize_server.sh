#!/bin/bash

# Check if the script is being run with bash
if [ -z "$BASH_VERSION" ]; then
    echo "Error: This script must be run with bash"
    exit 1
fi

# Define variables
SUDOERS_FILE="/etc/sudoers.d/server-setup"
NGINX_SCRIPT_URL="https://raw.githubusercontent.com/NearlyTRex/JoyBox/main/Bootstrap/managers/manager_nginx.sh"
CERTBOT_SCRIPT_URL="https://raw.githubusercontent.com/NearlyTRex/JoyBox/main/Bootstrap/managers/manager_certbot.sh"
COCKPIT_SCRIPT_URL="https://raw.githubusercontent.com/NearlyTRex/JoyBox/main/Bootstrap/managers/manager_cockpit.sh"
AZURACAST_SCRIPT_URL="https://raw.githubusercontent.com/NearlyTRex/JoyBox/main/Bootstrap/managers/manager_azuracast.sh"
APT_PACKAGES=(
    7zip
    apache2-utils
    apache2
    apt-file
    certbot
    cockpit
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

# Only run as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run this script as root (e.g., with sudo)"
    exit 1
fi

# Parse arguments
if [ $# -lt 3 ] || [ $# -gt 5 ]; then
    echo "Usage: $0 <local-username> <storage-user> <storage-host> [remote-path] [local-mount]"
    exit 1
fi
USERNAME="$1"
STORAGE_USER="$2"
STORAGE_HOST="$3"
STORAGE_REMOTE_PATH="${4:-/home}"
STORAGE_LOCAL_MOUNT="${5:-/mnt/storage}"

# Check that user exists
if ! id "$USERNAME" &>/dev/null; then
    echo "Error: User '$USERNAME' does not exist."
    exit 1
fi

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
    echo "Cmnd_Alias MANAGER_COCKPIT = /usr/local/bin/manager_cockpit.sh"
    echo "Cmnd_Alias MANAGER_AZURACAST = /usr/local/bin/manager_azuracast.sh"
    echo "$USERNAME ALL=(ALL) NOPASSWD: APT_MANAGE, MANAGER_NGINX, MANAGER_CERTBOT, MANAGER_COCKPIT, MANAGER_AZURACAST"
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

# Download and install manager scripts
echo "Downloading manager scripts..."
for url in "$NGINX_SCRIPT_URL" "$COCKPIT_SCRIPT_URL" "$CERTBOT_SCRIPT_URL" "$AZURACAST_SCRIPT_URL"; do
    script_name="/usr/local/bin/$(basename "$url")"
    if curl -fsSL -o "$script_name" "$url"; then
        chmod +x "$script_name"
        echo "Installed $(basename "$url")"
    else
        echo "Error: Failed to download $url"
        exit 1
    fi
done

# Install sshfs if needed
if ! command -v sshfs &>/dev/null; then
    apt-get install -y sshfs
fi

# Get paths
SSH_KEYGEN_BIN=$(command -v ssh-keygen)
SSH_COPY_ID_BIN=$(command -v ssh-copy-id)
SSHFS_BIN=$(command -v sshfs)

# Generate SSH key if not exists
SSH_KEY="/home/$USERNAME/.ssh/id_rsa"
if [ ! -f "$SSH_KEY" ]; then
    echo "Generating SSH key for $USERNAME..."
    sudo -u "$USERNAME" $SSH_KEYGEN_BIN -t rsa -b 4096 -N "" -f "$SSH_KEY"
fi

# Upload SSH public key
echo "Uploading SSH key..."
sudo -u "$USERNAME" "$SSH_COPY_ID_BIN" -p 23 -s -i "$SSH_KEY.pub" "$STORAGE_USER@$STORAGE_HOST"

# Create storage directory if it doesn't exist
if [ ! -d "$STORAGE_LOCAL_MOUNT" ]; then
    echo "Creating storage mount directory at $STORAGE_LOCAL_MOUNT..."
    mkdir -p "$STORAGE_LOCAL_MOUNT"
    chown "$USERNAME":"$USERNAME" "$STORAGE_LOCAL_MOUNT"
fi

# Create fstab entry
echo "Adding SSHFS mount to /etc/fstab..."
USER_UID=$(id -u "$USERNAME")
USER_GID=$(id -g "$USERNAME")
FSTAB_ENTRY="$STORAGE_USER@$STORAGE_HOST:$STORAGE_REMOTE_PATH $STORAGE_LOCAL_MOUNT fuse.sshfs noauto,x-systemd.automount,_netdev,user,idmap=user,identityfile=\"$SSH_KEY\",port=23,allow_other,uid=$USER_UID,gid=$USER_GID 0 0"
grep -qxF "$FSTAB_ENTRY" /etc/fstab || echo "$FSTAB_ENTRY" >> /etc/fstab

# Mount the SSHFS now
echo "Mounting storage box directory..."
sudo -u "$USERNAME" "$SSHFS_BIN" \
    -o IdentityFile="$SSH_KEY" \
    -o Port=23 \
    -o allow_other \
    -o uid="$USER_UID" \
    -o gid="$USER_GID" \
    "$STORAGE_USER@$STORAGE_HOST:$STORAGE_REMOTE_PATH" "$STORAGE_LOCAL_MOUNT"

# Make repositories folder
REPO_DIR="/home/$USERNAME/Repositories"
mkdir -p "$REPO_DIR"
chown "$USERNAME":"$USERNAME" "$REPO_DIR"

# Clone JoyBox repository
REPO_JOYBOX_DIR="/home/$USERNAME/Repositories/JoyBox"
if [ ! -d "$REPO_JOYBOX_DIR/.git" ]; then
    echo "Cloning JoyBox repository into $REPO_JOYBOX_DIR..."
    sudo -u "$USERNAME" git clone https://github.com/NearlyTRex/JoyBox "$REPO_JOYBOX_DIR"
else
    echo "JoyBox repository already cloned at $REPO_JOYBOX_DIR"
fi
