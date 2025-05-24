#!/bin/bash

NGINX_SCRIPT_URL="https://raw.githubusercontent.com/NearlyTRex/JoyBox/main/Bootstrap/managers/manager_nginx.sh"
CERTBOT_SCRIPT_URL="https://raw.githubusercontent.com/NearlyTRex/JoyBox/main/Bootstrap/managers/manager_certbot.sh"
COCKPIT_SCRIPT_URL="https://raw.githubusercontent.com/NearlyTRex/JoyBox/main/Bootstrap/managers/manager_cockpit.sh"
AZURACAST_SCRIPT_URL="https://raw.githubusercontent.com/NearlyTRex/JoyBox/main/Bootstrap/managers/manager_azuracast.sh"

ensure_bash_shell() {
    if [ -z "$BASH_VERSION" ]; then
        echo "Error: This script must be run with bash"
        exit 1
    fi
}

ensure_root_user() {
    if [ "$EUID" -ne 0 ]; then
        echo "Error: Please run this script as root (e.g., with sudo)"
        exit 1
    fi
}

check_user_exists() {
    local username="$1"

    if ! id "$username" &>/dev/null; then
        echo "Error: User '$username' does not exist."
        exit 1
    fi
}

load_packages() {
    local package_file="$1"

    if [[ ! -f "$package_file" ]]; then
        echo "Error: Package list file '$package_file' not found."
        exit 1
    fi

    mapfile -t APT_PACKAGES < <(grep -Ev '^\s*#|^\s*$' "$package_file")

    if [[ ${#APT_PACKAGES[@]} -eq 0 ]]; then
        echo "Error: No valid packages found in '$package_file'"
        exit 1
    fi
}

setup_sudoers() {
    local username="$1"
    local sudoers_file="$2"

    local temp_file=$(mktemp)
    {
        echo "Cmnd_Alias APT_MANAGE = \\"
        echo "    /usr/bin/apt-get update, \\"
        echo "    /usr/bin/apt-get autoremove -y, \\"
        local last_index=$((${#APT_PACKAGES[@]} - 1))
        for i in "${!APT_PACKAGES[@]}"; do
            local pkg="${APT_PACKAGES[$i]}"
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
        echo "$username ALL=(ALL) NOPASSWD: APT_MANAGE, MANAGER_NGINX, MANAGER_CERTBOT, MANAGER_COCKPIT, MANAGER_AZURACAST"
    } > "$temp_file"

    if visudo -c -f "$temp_file"; then
        mv "$temp_file" "$sudoers_file"
        chmod 0440 "$sudoers_file"
        echo "Sudoers configuration installed at $sudoers_file"
    else
        echo "Error: Invalid sudoers syntax. Aborting."
        rm -f "$temp_file"
        exit 1
    fi
}

cleanup_sudoers() {
    local sudoers_file="$1"

    if [ -f "$sudoers_file" ]; then
        rm -f "$sudoers_file"
        echo "Removed sudoers file at $sudoers_file"
    else
        echo "No sudoers file to remove at $sudoers_file"
    fi
}

configure_docker_group() {
    local username="$1"

    if ! getent group docker > /dev/null 2>&1; then
        echo "Docker group does not exist. Creating the docker group."
        groupadd docker
    fi

    if groups "$username" | grep -qw docker; then
        echo "User '$username' is already in the 'docker' group."
    else
        usermod -aG docker "$username"
        echo "Added '$username' to the 'docker' group. You may need to re-login to apply group changes."
    fi
}

install_manager_scripts() {
    mkdir -p /usr/local/bin
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
}

setup_storage_box() {
    local username="$1"
    local storage_user="$2"
    local storage_host="$3"
    local storage_remote_path="${4:-/home}"
    local storage_local_mount="${5:-/mnt/storage}"

    if ! command -v sshfs &>/dev/null; then
        apt-get install -y sshfs
    fi

    local ssh_key="/home/$username/.ssh/id_rsa"
    local ssh_keygen_bin=$(command -v ssh-keygen)
    local ssh_copy_id_bin=$(command -v ssh-copy-id)
    local sshfs_bin=$(command -v sshfs)
    local user_uid=$(id -u "$username")
    local user_gid=$(id -g "$username")

    if [ ! -f "$ssh_key" ]; then
        echo "Generating SSH key for $username..."
        sudo -u "$username" $ssh_keygen_bin -t rsa -b 4096 -N "" -f "$ssh_key"
    fi

    echo "Uploading SSH key..."
    sudo -u "$username" "$ssh_copy_id_bin" -p 23 -s -i "$ssh_key.pub" "$STORAGE_USER@$storage_host"

    if [ ! -d "$storage_local_mount" ]; then
        echo "Creating storage mount directory at $storage_local_mount..."
        mkdir -p "$storage_local_mount"
        chown "$username":"$username" "$storage_local_mount"
    fi

    echo "Adding SSHFS mount to /etc/fstab..."
    local fstab_entry="$storage_user@$storage_host:$storage_remote_path $storage_local_mount fuse.sshfs noauto,x-systemd.automount,_netdev,user,idmap=user,identityfile=\"$ssh_key\",port=23,allow_other,uid=$user_uid,gid=$user_gid 0 0"
    grep -qxF "$fstab_entry" /etc/fstab || echo "$fstab_entry" >> /etc/fstab

    if ! mountpoint -q "$storage_local_mount"; then
        echo "Mounting storage box directory..."
        sudo -u "$username" "$sshfs_bin" \
            -o IdentityFile="$ssh_key" \
            -o Port=23 \
            -o allow_other \
            -o uid="$user_uid" \
            -o gid="$user_gid" \
            "$storage_user@$storage_host:$storage_remote_path" "$storage_local_mount"
    else
        echo "$storage_local_mount is already mounted."
    fi
}

clone_joybox_repo() {
    local username="$1"
    local repo_dir="/home/$username/Repositories"
    local repo_joybox_dir="$repo_dir/JoyBox"

    mkdir -p "$repo_dir"
    chown "$username":"$username" "$repo_dir"

    if [ ! -d "$repo_joybox_dir/.git" ]; then
        echo "Cloning JoyBox repository into $repo_joybox_dir..."
        sudo -u "$username" git clone https://github.com/NearlyTRex/JoyBox "$repo_joybox_dir"
    else
        echo "JoyBox repository already cloned at $repo_joybox_dir"
    fi
}
