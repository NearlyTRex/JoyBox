#!/bin/bash

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
    echo "Loading APT packages from $package_file..."

    if [[ ! -f "$package_file" ]]; then
        echo "Error: Package list file '$package_file' not found."
        exit 1
    fi

    mapfile -t APT_PACKAGES < <(grep -Ev '^\s*#|^\s*$' "$package_file")

    if [[ ${#APT_PACKAGES[@]} -eq 0 ]]; then
        echo "Error: No valid packages found in '$package_file'"
        exit 1
    fi

    echo "Loaded ${#APT_PACKAGES[@]} packages."
}

load_managers() {
    local manager_file="$1"
    echo "Loading manager scripts from $manager_file..."

    if [[ ! -f "$manager_file" ]]; then
        echo "Error: Manager list file '$manager_file' not found."
        exit 1
    fi

    mapfile -t MANAGERS < <(grep -Ev '^\s*#|^\s*$' "$manager_file")

    if [[ ${#MANAGERS[@]} -eq 0 ]]; then
        echo "Error: No valid manager scripts found in '$manager_file'"
        exit 1
    fi

    echo "Loaded ${#MANAGERS[@]} manager scripts."
}

install_managers() {
    echo "Installing manager scripts..."
    mkdir -p /usr/local/bin

    for script in "${MANAGERS[@]}"; do
        local url="https://raw.githubusercontent.com/NearlyTRex/JoyBox/main/Bootstrap/managers/$script"
        local script_path="/usr/local/bin/$script"
        echo "Downloading $script from $url..."
        if curl -fsSL -o "$script_path" "$url"; then
            chmod +x "$script_path"
            echo "Installed $script to $script_path"
        else
            echo "Error: Failed to download $url"
            exit 1
        fi
    done
}

setup_sudoers() {
    local username="$1"
    local sudoers_file="$2"
    echo "Configuring sudoers file at $sudoers_file for user $username..."

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

        local aliases=()
        for script in "${MANAGERS[@]}"; do
            local name="${script%.sh}"
            local alias_name="MANAGER_${name^^}"
            echo "Cmnd_Alias $alias_name = /usr/local/bin/$script"
            aliases+=("$alias_name")
        done

        echo "$username ALL=(ALL) NOPASSWD: APT_MANAGE, ${aliases[*]}"
    } > "$temp_file"

    if visudo -c -f "$temp_file"; then
        mv "$temp_file" "$sudoers_file"
        chmod 0440 "$sudoers_file"
        echo "Sudoers configuration installed."
    else
        echo "Error: Invalid sudoers syntax. Aborting."
        rm -f "$temp_file"
        exit 1
    fi
}

cleanup_sudoers() {
    local sudoers_file="$1"
    echo "Cleaning up sudoers file $sudoers_file..."

    if [ -f "$sudoers_file" ]; then
        rm -f "$sudoers_file"
        echo "Removed sudoers file."
    else
        echo "No sudoers file to remove."
    fi
}

add_htpasswd_user() {
    local username="$1"
    local password="$2"
    local htpasswd_file="/etc/nginx/.htpasswd"
    echo "Configuring htpasswd for user '$username'..."

    if ! command -v htpasswd &>/dev/null; then
        echo "Installing apache2-utils for htpasswd..."
        apt-get update
        apt-get install -y apache2-utils
    fi

    if [ ! -f "$htpasswd_file" ]; then
        echo "Creating new htpasswd file at $htpasswd_file"
        htpasswd -cbB "$htpasswd_file" "$username" "$password"
        chmod 640 "$htpasswd_file"
        chown root:www-data "$htpasswd_file"
    else
        echo "Updating user '$username' in htpasswd file..."
        htpasswd -bB "$htpasswd_file" "$username" "$password"
    fi
}

remove_htpasswd() {
    local htpasswd_file="/etc/nginx/.htpasswd"
    echo "Removing htpasswd file..."
    if [ -f "$htpasswd_file" ]; then
        rm -f "$htpasswd_file"
        echo "Removed htpasswd file."
    else
        echo "No htpasswd file found."
    fi
}

configure_unattended_upgrades() {
    echo "Configuring unattended-upgrades..."
    apt-get update
    apt-get install -y unattended-upgrades
    dpkg-reconfigure -f noninteractive unattended-upgrades
    echo "Unattended-upgrades configuration complete."
}

configure_ufw_firewall() {
    echo "Configuring UFW firewall..."
    apt-get update
    apt-get install -y ufw
    ufw allow OpenSSH
    ufw allow 'Nginx Full'
    ufw --force enable
    echo "UFW firewall configuration complete."
}

configure_fail2ban() {
    echo "Configuring Fail2Ban..."
    apt-get update
    apt-get install -y fail2ban

    echo "Creating Fail2Ban jail configuration for NGINX..."
    cat > /etc/fail2ban/jail.d/nginx-auth.conf <<EOF
[nginx-http-auth]
enabled  = true
port     = http,https
filter   = nginx-http-auth
logpath  = /var/log/nginx/error.log
maxretry = 3
bantime  = 3600
EOF

    echo "Restarting Fail2Ban..."
    systemctl restart fail2ban
    echo "Fail2Ban configuration complete."
}

configure_security_headers() {
    echo "Configuring NGINX security headers..."
    cat > /etc/nginx/snippets/ssl-params.conf <<EOF
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers 'EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH';
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
add_header X-Content-Type-Options nosniff;
add_header X-Frame-Options DENY;
add_header X-XSS-Protection "1; mode=block";
add_header Referrer-Policy "strict-origin-when-cross-origin";
add_header Permissions-Policy "geolocation=(), microphone=()";
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
EOF
    echo "NGINX security headers configuration complete."
}

configure_rate_limit() {
    echo "Configuring NGINX rate limiting..."
    cat > /etc/nginx/snippets/rate-limit.conf <<EOF
limit_req_zone \$binary_remote_addr zone=mylimit:10m rate=5r/s;
EOF
    echo "NGINX rate limiting configuration complete."
}

configure_modsecurity() {
    local modsec_dir="/etc/nginx/modsec"
    echo "Configuring ModSecurity..."

    apt-get update
    apt-get install -y libnginx-mod-http-modsecurity curl git

    echo "Creating ModSecurity directory..."
    mkdir -p "$modsec_dir"

    echo "Downloading modsecurity.conf-recommended..."
    curl -fsSL -o "$modsec_dir/modsecurity.conf" https://raw.githubusercontent.com/SpiderLabs/ModSecurity/v3/master/modsecurity.conf-recommended

    echo "Enabling ModSecurity..."
    sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' "$modsec_dir/modsecurity.conf"

    echo "Cloning Core Rule Set (CRS)..."
    git clone --depth 1 https://github.com/coreruleset/coreruleset "$modsec_dir/crs"
    cp "$modsec_dir/crs/crs-setup.conf.example" "$modsec_dir/crs/crs-setup.conf"

    echo "Creating main ModSecurity config include file..."
    cat > "$modsec_dir/main.conf" <<EOF
include $modsec_dir/modsecurity.conf;
include $modsec_dir/crs/crs-setup.conf;
include $modsec_dir/crs/rules/*.conf;
EOF

    echo "ModSecurity configuration complete."
}

configure_docker_group() {
    local username="$1"
    echo "Configuring Docker group access for $username..."

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

    echo "Docker group configuration complete."
}

configure_docker_security() {
    echo "Configuring Docker daemon security..."
    mkdir -p /etc/docker

    cat > /etc/docker/daemon.json <<EOF
{
  "no-new-privileges": true,
  "userns-remap": "default",
  "log-driver": "journald",
  "live-restore": true
}
EOF

    echo "Applying iptables security rule..."
    iptables -C DOCKER-USER -i docker0 -d 169.254.169.254 -j DROP 2>/dev/null || \
    iptables -I DOCKER-USER -i docker0 -d 169.254.169.254 -j DROP

    echo "Restarting Docker service..."
    systemctl restart docker
    echo "Docker security configuration complete."
}

setup_storage_box() {
    local username="$1"
    local storage_user="$2"
    local storage_host="$3"
    local storage_remote_path="${4:-/home}"
    local storage_local_mount="${5:-/mnt/storage}"

    if ! command -v sshfs &>/dev/null; then
        echo "Installing sshfs..."
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

    echo "Uploading SSH key to $storage_host..."
    sudo -u "$username" "$ssh_copy_id_bin" -p 23 -s -i "$ssh_key.pub" "$storage_user@$storage_host"

    if [ ! -d "$storage_local_mount" ]; then
        echo "Creating local mount directory at $storage_local_mount..."
        mkdir -p "$storage_local_mount"
        chown "$username":"$username" "$storage_local_mount"
    fi

    echo "Adding mount entry to /etc/fstab..."
    local fstab_entry="$storage_user@$storage_host:$storage_remote_path $storage_local_mount fuse.sshfs noauto,x-systemd.automount,_netdev,user,idmap=user,identityfile=\"$ssh_key\",port=23,allow_other,uid=$user_uid,gid=$user_gid 0 0"
    grep -qxF "$fstab_entry" /etc/fstab || echo "$fstab_entry" >> /etc/fstab

    if ! mountpoint -q "$storage_local_mount"; then
        echo "Mounting storage directory..."
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

setup_joybox_repo() {
    local username="$1"
    local repo_dir="/home/$username/Repositories"
    local repo_joybox_dir="$repo_dir/JoyBox"

    echo "Setting up JoyBox repository..."
    mkdir -p "$repo_dir"
    chown "$username":"$username" "$repo_dir"
    if [ ! -d "$repo_joybox_dir/.git" ]; then
        echo "Cloning into $repo_joybox_dir..."
        sudo -u "$username" git clone https://github.com/NearlyTRex/JoyBox "$repo_joybox_dir"
    else
        echo "JoyBox repository already exists at $repo_joybox_dir"
    fi
}
