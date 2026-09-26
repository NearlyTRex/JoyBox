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
    local managers_dir="${1:-}"
    echo "Installing manager scripts..."
    mkdir -p /usr/local/bin

    for script in "${MANAGERS[@]}"; do
        local script_path="/usr/local/bin/$script"

        # Prefer the checkout this script is running from, so a manager change
        # takes effect without first being pushed to the remote branch. The
        # package and manager lists are already read locally, so downloading
        # the managers themselves from a branch was the odd one out.
        if [[ -n "$managers_dir" && -r "$managers_dir/$script" ]]; then
            echo "Installing $script from $managers_dir..."
            cp "$managers_dir/$script" "$script_path"
            chmod +x "$script_path"
            echo "Installed $script to $script_path"
            continue
        fi

        # Downloading is opt-in. setup_sudoers grants this user passwordless root
        # on every script in /usr/local/bin/manager_*.sh, so installing one from an
        # unverified fetch hands root to whoever can answer for that host.
        if [[ "${JOYBOX_ALLOW_MANAGER_DOWNLOAD:-}" != "1" ]]; then
            echo "Error: $script was not found in a local checkout."
            echo "Run this from a JoyBox checkout, or pass the directory explicitly:"
            echo "  install_managers /path/to/JoyBox/Bootstrap/managers"
            echo
            echo "To fetch from GitHub instead - these scripts get passwordless sudo,"
            echo "so only do this on a host you trust - re-run with:"
            echo "  JOYBOX_ALLOW_MANAGER_DOWNLOAD=1 $0"
            exit 1
        fi

        local url="https://raw.githubusercontent.com/NearlyTRex/JoyBox/main/Bootstrap/managers/$script"
        echo "Downloading $script from $url..."
        if curl -fsSL --proto '=https' --tlsv1.2 -o "$script_path" "$url"; then
            chmod +x "$script_path"
            echo "Installed $script to $script_path"
        else
            echo "Error: Failed to download $url"
            echo "Hint: run this from a JoyBox checkout so the local copy is used instead."
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

        # Read-only checks verify_server runs, so a hardened server can still
        # be verified once root login is closed
        echo "Cmnd_Alias JOYBOX_VERIFY = \\"
        echo "    /usr/sbin/ufw status, \\"
        echo "    /usr/sbin/sshd -T, \\"
        echo "    /usr/bin/fail2ban-client status sshd, \\"
        echo "    /usr/bin/fail2ban-client status nginx-http-auth, \\"
        echo "    /usr/sbin/nginx -T"
        echo ""

        local aliases=()
        for script in "${MANAGERS[@]}"; do
            local name="${script#manager_}"
            local name="${name%.sh}"
            local alias_name="MANAGER_${name^^}"
            echo "Cmnd_Alias $alias_name = /usr/local/bin/$script"
            aliases+=("$alias_name")
        done

        (IFS=', '; echo "$username ALL=(ALL) NOPASSWD: APT_MANAGE, JOYBOX_VERIFY, ${aliases[*]}")
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
    else
        echo "Updating user '$username' in htpasswd file..."
        htpasswd -bB "$htpasswd_file" "$username" "$password"
    fi

    # Asserted on both paths, not just creation: if anything upstream ever reset
    # the file to default permissions, an update would otherwise leave it readable.
    chmod 640 "$htpasswd_file"
    chown root:www-data "$htpasswd_file"
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

    # Pin the schedule explicitly rather than inheriting whatever debconf defaults
    # ship. Without Automatic-Reboot the box installs kernel and libc updates but
    # keeps running the old ones, so it reports patched while still vulnerable.
    cat > /etc/apt/apt.conf.d/52-joybox-unattended <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-WithUsers "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
EOF

    systemctl enable --now unattended-upgrades 2>/dev/null || true
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

    # SSH jail. The distro default watches /var/log/auth.log, which does not exist
    # on Ubuntu 24.04+ because sshd logs only to journald and rsyslog is no longer
    # installed - so the packaged jail silently matches nothing. Force the systemd
    # backend and assert the jail here rather than relying on the default.
    echo "Creating Fail2Ban jail configuration for SSH..."
    cat > /etc/fail2ban/jail.d/sshd.conf <<EOF
[sshd]
enabled  = true
port     = ssh
filter   = sshd
backend  = systemd
maxretry = 3
findtime = 600
bantime  = 3600
EOF

    echo "Restarting Fail2Ban..."
    systemctl restart fail2ban
    echo "Fail2Ban configuration complete."
}

configure_security_headers() {
    echo "Configuring NGINX security headers..."
    cat > /etc/nginx/snippets/ssl-params.conf <<EOF
# The version banner is free reconnaissance; turn it off everywhere.
server_tokens off;

# Apply the zone defined in rate-limit.conf. Defining limit_req_zone alone does
# nothing - without a limit_req directive consuming it, no request is ever limited.
# Included per-server, so it covers every vhost that includes this snippet.
limit_req zone=mylimit burst=20 nodelay;

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

    # HTTP/2 is enabled here rather than on each "listen" line: the
    # "listen ... http2" form is deprecated from nginx 1.25.1, and setting it on
    # some 443 blocks but not others triggers "protocol options redefined". The
    # directive form does not exist before 1.25.1, so only add it when supported.
    local nginx_version
    nginx_version=$(nginx -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    if [ -n "$nginx_version" ] && [ "$(printf '%s\n1.25.1\n' "$nginx_version" | sort -V | head -1)" = "1.25.1" ]; then
        echo "http2 on;" >> /etc/nginx/snippets/ssl-params.conf
        echo "Enabled HTTP/2 for nginx $nginx_version"
    else
        echo "nginx ${nginx_version:-unknown} predates the http2 directive, leaving HTTP/2 off"
    fi

    echo "NGINX security headers configuration complete."
}

configure_rate_limit() {
    echo "Configuring NGINX rate limiting..."
    cat > /etc/nginx/snippets/rate-limit.conf <<EOF
limit_req_zone \$binary_remote_addr zone=mylimit:10m rate=5r/s;
EOF

    if ! grep -q "include /etc/nginx/snippets/rate-limit.conf" /etc/nginx/nginx.conf; then
        sed -i '/##[[:space:]]*# Basic Settings/,/##[[:space:]]*$/{
            /##[[:space:]]*$/a\\n\t# Rate Limiting\n\tinclude /etc/nginx/snippets/rate-limit.conf;\n
        }' /etc/nginx/nginx.conf

        if ! grep -q "include /etc/nginx/snippets/rate-limit.conf" /etc/nginx/nginx.conf; then
            sed -i '/default_type application\/octet-stream;/a\\n\t# Rate Limiting\n\tinclude /etc/nginx/snippets/rate-limit.conf;\n' /etc/nginx/nginx.conf
        fi
        echo "Rate limiting include added to nginx.conf"
    else
        echo "Rate limiting include already exists in nginx.conf"
    fi
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
    if [ ! -f "$modsec_dir/modsecurity.conf" ]; then
        curl -fsSL -o "$modsec_dir/modsecurity.conf" https://raw.githubusercontent.com/SpiderLabs/ModSecurity/v3/master/modsecurity.conf-recommended
        echo "Downloaded modsecurity.conf"
    else
        echo "modsecurity.conf already exists"
    fi

    echo "Enabling ModSecurity..."
    sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' "$modsec_dir/modsecurity.conf"

    # Pinned rather than tracking a branch, matching the "never latest" policy the
    # container image pins follow. A rule set that changes under you can start
    # blocking legitimate traffic on an unrelated rerun. Bump deliberately.
    local crs_version="v4.29.0"

    echo "Setting up Core Rule Set (CRS) $crs_version..."
    if [ -d "$modsec_dir/crs" ] && [ ! -d "$modsec_dir/crs/.git" ]; then
        echo "CRS directory exists but is not a git repository. Removing..."
        rm -rf "$modsec_dir/crs"
    fi

    if [ ! -d "$modsec_dir/crs" ]; then
        echo "Cloning Core Rule Set at $crs_version..."
        git clone --depth 1 --branch "$crs_version" \
            https://github.com/coreruleset/coreruleset "$modsec_dir/crs"
        echo "CRS cloned successfully"
    else
        echo "Checking out CRS $crs_version..."
        git -C "$modsec_dir/crs" fetch --depth 1 origin "refs/tags/$crs_version:refs/tags/$crs_version" 2>/dev/null || true
        if ! git -C "$modsec_dir/crs" checkout -q "$crs_version" 2>/dev/null; then
            echo "Warning: could not check out $crs_version, using existing version"
        fi
    fi

    echo "Setting up CRS configuration..."
    if [ ! -f "$modsec_dir/crs/crs-setup.conf" ]; then
        if [ -f "$modsec_dir/crs/crs-setup.conf.example" ]; then
            cp "$modsec_dir/crs/crs-setup.conf.example" "$modsec_dir/crs/crs-setup.conf"
            echo "Created crs-setup.conf from example"
        else
            echo "Warning: crs-setup.conf.example not found, creating basic configuration"
            cat > "$modsec_dir/crs/crs-setup.conf" <<EOF
# Basic CRS setup configuration
# Generated automatically by bootstrap script
SecDefaultAction "phase:1,log,auditlog,deny,status:403"
SecDefaultAction "phase:2,log,auditlog,deny,status:403"
EOF
        fi
    else
        echo "crs-setup.conf already exists"
    fi

    echo "Creating main ModSecurity config include file..."
    cat > "$modsec_dir/main.conf" <<EOF
include $modsec_dir/modsecurity.conf;
include $modsec_dir/crs/crs-setup.conf;
include $modsec_dir/crs/rules/*.conf;
EOF

    echo "Verifying ModSecurity setup..."
    if [ -f "$modsec_dir/main.conf" ] && [ -f "$modsec_dir/modsecurity.conf" ] && [ -d "$modsec_dir/crs/rules" ]; then
        rule_count=$(find "$modsec_dir/crs/rules" -name "*.conf" | wc -l)
        echo "ModSecurity configuration complete"
        echo "Found $rule_count CRS rule files"
    else
        echo "Warning: ModSecurity setup may be incomplete"
        echo "Please check the configuration manually"
    fi
    echo "ModSecurity configuration complete."
}

configure_nginx_stream_module() {
    echo "Configuring NGINX stream module..."

    if ! dpkg -l | grep -q libnginx-mod-stream; then
        echo "Installing NGINX stream module..."
        apt-get update
        apt-get install -y libnginx-mod-stream
    else
        echo "NGINX stream module package already installed"
    fi

    echo "Creating stream configuration directories..."
    mkdir -p /etc/nginx/streams-available
    mkdir -p /etc/nginx/streams-enabled

    echo "Ensuring stream module is loaded..."
    if ! grep -q "load_module.*ngx_stream_module" /etc/nginx/nginx.conf; then
        cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup
        sed -i '1i load_module modules/ngx_stream_module.so;' /etc/nginx/nginx.conf
        echo "Added stream module load directive"
    else
        echo "Stream module load directive already exists"
    fi

    echo "Updating nginx.conf to include stream configuration..."
    if ! grep -q "stream {" /etc/nginx/nginx.conf; then
        [ ! -f /etc/nginx/nginx.conf.backup ] && cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup
        sed -i '/^http {/i\\n# Stream module configuration\nstream {\n\tinclude /etc/nginx/streams-enabled/*;\n}' /etc/nginx/nginx.conf
        echo "Stream block added to nginx.conf"
    else
        echo "Stream block already exists in nginx.conf"
    fi

    if nginx -t; then
        echo "NGINX stream module configuration complete"
        systemctl reload nginx
    else
        echo "Error: NGINX configuration test failed"
        if [ -f /etc/nginx/nginx.conf.backup ]; then
            mv /etc/nginx/nginx.conf.backup /etc/nginx/nginx.conf
            echo "Restored nginx.conf from backup"
        fi
        exit 1
    fi
}

configure_sshd_hardening() {
    local username="$1"
    echo "Hardening sshd for user $username..."

    # Refuse to lock the box out of itself: without an authorized key for this
    # user, disabling password auth leaves no way back in but the provider console.
    local auth_keys="/home/$username/.ssh/authorized_keys"
    if [[ ! -s "$auth_keys" ]]; then
        echo "Error: $auth_keys is missing or empty."
        echo "Install a public key for $username and verify key login works before running this."
        exit 1
    fi

    # A drop-in rather than edits to sshd_config: re-running is idempotent, and
    # the packaged config keeps receiving distro updates untouched.
    mkdir -p /etc/ssh/sshd_config.d
    cat > /etc/ssh/sshd_config.d/99-joybox.conf <<EOF
# Managed by JoyBox - see Bootstrap/scripts/init_sshd.sh
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
AllowUsers $username
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
    chmod 644 /etc/ssh/sshd_config.d/99-joybox.conf

    # Older releases do not Include the drop-in directory. Adding the config
    # without that line would be a silent no-op.
    if ! grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config; then
        echo "Adding Include directive to /etc/ssh/sshd_config..."
        sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
    fi

    # Validate before touching the running daemon; a bad config here is a lockout.
    if ! sshd -t; then
        echo "Error: sshd configuration is invalid. Reverting."
        rm -f /etc/ssh/sshd_config.d/99-joybox.conf
        exit 1
    fi

    # Reload, not restart: existing sessions survive, so a mistake is recoverable
    # from the shell you already have open.
    systemctl reload ssh 2>/dev/null || systemctl reload sshd
    echo "sshd hardening complete. Keep this session open and verify key login from a second terminal."
}

install_docker() {
    echo "Installing Docker..."
    apt-get update
    apt-get install -y docker.io
    systemctl enable --now docker
    echo "Docker installation complete."
}

install_nginx() {
    echo "Installing NGINX..."
    apt-get update
    apt-get install -y nginx
    systemctl enable --now nginx
    echo "NGINX installation complete."
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
    local password_file="${6:-}"

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

    # Unattended, the password comes from a file through sshpass, and the host
    # key is accepted on first sight since no one is there to confirm it
    echo "Uploading SSH key to $storage_host..."
    if [ -n "$password_file" ]; then
        if ! command -v sshpass &>/dev/null; then
            echo "Installing sshpass..."
            apt-get install -y sshpass
        fi
        chown "$username" "$password_file"
        sudo -u "$username" sshpass -f "$password_file" "$ssh_copy_id_bin" \
            -o StrictHostKeyChecking=accept-new -p 23 -s -i "$ssh_key.pub" "$storage_user@$storage_host"
    else
        sudo -u "$username" "$ssh_copy_id_bin" -p 23 -s -i "$ssh_key.pub" "$storage_user@$storage_host"
    fi

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
    local repo_dir="${2:-/mnt/repositories}"

    if [ ! -d "$repo_dir" ]; then
        echo "Creating repository directory at $repo_dir..."
        mkdir -p "$repo_dir"
        chown "$username":"$username" "$repo_dir"
    fi

    echo "Setting up JoyBox repository..."
    local repo_joybox_dir="$repo_dir/JoyBox"
    if [ ! -d "$repo_joybox_dir/.git" ]; then
        echo "Cloning into $repo_joybox_dir..."
        sudo -u "$username" git clone https://github.com/NearlyTRex/JoyBox "$repo_joybox_dir"
    else
        echo "JoyBox repository already exists at $repo_joybox_dir"
    fi
}

###########################################################
# Local storage substitute
#
# Stands in for the Hetzner Storage Box on the rehearsal VM. Everything
# downstream just wants a path with files under it, so a plain directory is
# enough and a loopback image would add ceremony for no extra coverage.
#
# Known gap, stated rather than faked: this does not exercise sshfs itself -
# mount flags, idmap, _netdev ordering, or off-box durability.
###########################################################

setup_local_storage() {
    local username="$1"
    local mount_path="${2:-/mnt/storage}"

    echo "Creating local storage at $mount_path..."
    mkdir -p "$mount_path/Music/Audiobook"
    mkdir -p "$mount_path/Backups"
    chown -R "$username":"$username" "$mount_path"

    # Seed placeholder media so library scans have something to find. Silence is
    # fine - the point is that the scanners see a real file, not that it plays.
    if command -v ffmpeg &>/dev/null; then
        if [[ ! -f "$mount_path/Music/placeholder.mp3" ]]; then
            echo "Generating placeholder media with ffmpeg..."
            ffmpeg -loglevel error -f lavfi -i anullsrc=r=44100:cl=mono -t 2 \
                -metadata title="JoyBox Test Track" \
                -metadata artist="JoyBox" \
                -metadata album="Local Testing" \
                "$mount_path/Music/placeholder.mp3"
            cp "$mount_path/Music/placeholder.mp3" "$mount_path/Music/Audiobook/placeholder.mp3"
            chown -R "$username":"$username" "$mount_path/Music"
        fi
    else
        echo "Note: ffmpeg is not installed, so no placeholder media was created."
        echo "The directories exist, but the library scanners will find them empty."
    fi

    echo
    echo "Local storage ready:"
    find "$mount_path" -maxdepth 2 | sed 's/^/  /'
}
