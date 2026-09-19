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

        local aliases=()
        for script in "${MANAGERS[@]}"; do
            local name="${script#manager_}"
            local name="${name%.sh}"
            local alias_name="MANAGER_${name^^}"
            echo "Cmnd_Alias $alias_name = /usr/local/bin/$script"
            aliases+=("$alias_name")
        done

        (IFS=', '; echo "$username ALL=(ALL) NOPASSWD: APT_MANAGE, ${aliases[*]}")
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
# Local test VM
#
# Workstation-side helpers for the rehearsal VM described in
# docs/local-testing.md. A real KVM guest rather than a container because the
# things being rehearsed - ufw, a Docker daemon with userns-remap, and sshd
# itself - all need their own kernel-facing stack to mean anything.
#
# These run on the workstation. setup_local_storage and the verify_* functions
# below run on the VM itself.
###########################################################

TESTVM_IMAGE_DIR="/var/lib/libvirt/images"

require_test_vm_tools() {
    local tool
    for tool in virt-install virsh qemu-img cloud-localds; do
        if ! command -v "$tool" &>/dev/null; then
            echo "Error: $tool is not installed."
            echo "Install the workstation prerequisites with:"
            echo "  python3 bootstrap.py -a setup -t local_ubuntu --components aptget"
            return 1
        fi
    done
}

test_vm_exists() {
    virsh dominfo "$1" &>/dev/null
}

get_test_vm_ip() {
    local vm_name="$1"
    virsh domifaddr "$vm_name" 2>/dev/null | awk '/ipv4/ {print $4}' | cut -d/ -f1 | head -n1
}

resolve_ssh_public_key() {
    local username="$1"
    local explicit="${2:-}"

    if [[ -n "$explicit" ]]; then
        if [[ ! -r "$explicit" ]]; then
            echo "Error: cannot read SSH public key at $explicit" >&2
            return 1
        fi
        echo "$explicit"
        return 0
    fi

    local candidate
    for candidate in "/home/$username/.ssh/id_ed25519.pub" "/home/$username/.ssh/id_rsa.pub"; do
        if [[ -r "$candidate" ]]; then
            echo "$candidate"
            return 0
        fi
    done

    echo "Error: no SSH public key found for $username. Generate one with:" >&2
    echo "  ssh-keygen -t ed25519" >&2
    return 1
}

create_test_vm() {
    local vm_name="${1:-joybox-test}"
    local username="${2:-${SUDO_USER:-$USER}}"
    local ssh_key="${3:-}"
    local memory="${4:-4096}"
    local vcpus="${5:-2}"
    local disk_size="${6:-20}"
    local release="${7:-noble}"
    local console_password="${8:-joybox}"

    require_test_vm_tools || return 1

    if test_vm_exists "$vm_name"; then
        echo "Error: a VM named '$vm_name' already exists."
        echo "Remove it first:  sudo $0 destroy --name $vm_name"
        return 1
    fi

    local ssh_key_path
    ssh_key_path="$(resolve_ssh_public_key "$username" "$ssh_key")" || return 1
    local ssh_key_contents
    ssh_key_contents="$(cat "$ssh_key_path")"

    # Fetch the base cloud image once and reuse it across VMs
    local base_image="$TESTVM_IMAGE_DIR/${release}-server-cloudimg-amd64.img"
    if [[ ! -f "$base_image" ]]; then
        echo "Downloading the $release cloud image..."
        mkdir -p "$TESTVM_IMAGE_DIR"
        curl -fL --proto '=https' --tlsv1.2 -o "$base_image" \
            "https://cloud-images.ubuntu.com/${release}/current/${release}-server-cloudimg-amd64.img"
    fi

    local vm_disk="$TESTVM_IMAGE_DIR/${vm_name}.qcow2"
    echo "Creating a ${disk_size}G disk at $vm_disk..."
    qemu-img create -f qcow2 -F qcow2 -b "$base_image" "$vm_disk" "${disk_size}G"

    # cloud-init seeds BOTH a key and a console password on purpose: init_sshd.sh
    # disables password SSH, so "virsh console" is the only way back in if the key
    # ever stops working.
    local seed_dir
    seed_dir="$(mktemp -d)"

    cat > "$seed_dir/user-data" <<CLOUDINIT
#cloud-config
hostname: $vm_name
users:
  - name: $username
    groups: [sudo]
    shell: /bin/bash
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    lock_passwd: false
    ssh_authorized_keys:
      - $ssh_key_contents
chpasswd:
  list: |
    $username:$console_password
  expire: false
ssh_pwauth: true
package_update: true
packages:
  - openssh-server
runcmd:
  - [ systemctl, enable, --now, ssh ]
CLOUDINIT

    cat > "$seed_dir/meta-data" <<CLOUDINIT
instance-id: $vm_name
local-hostname: $vm_name
CLOUDINIT

    local seed_image="$TESTVM_IMAGE_DIR/${vm_name}-seed.iso"
    cloud-localds "$seed_image" "$seed_dir/user-data" "$seed_dir/meta-data"
    rm -rf "$seed_dir"

    if ! virsh net-info default 2>/dev/null | grep -q "Active:.*yes"; then
        echo "Starting the default libvirt network..."
        virsh net-start default 2>/dev/null || true
        virsh net-autostart default 2>/dev/null || true
    fi

    echo "Creating VM '$vm_name'..."
    virt-install \
        --name "$vm_name" \
        --memory "$memory" \
        --vcpus "$vcpus" \
        --disk "path=$vm_disk,device=disk,bus=virtio" \
        --disk "path=$seed_image,device=cdrom" \
        --os-variant "ubuntu22.04" \
        --network network=default,model=virtio \
        --graphics none \
        --console pty,target_type=serial \
        --import \
        --noautoconsole

    echo "Waiting for the VM to get an address..."
    local vm_ip=""
    local attempt
    for attempt in $(seq 1 60); do
        vm_ip="$(get_test_vm_ip "$vm_name")"
        if [[ -n "$vm_ip" ]]; then
            break
        fi
        sleep 5
    done

    if [[ -z "$vm_ip" ]]; then
        echo "Warning: could not determine the VM's address yet."
        echo "Check with: sudo virsh domifaddr $vm_name"
        return 0
    fi

    echo
    echo "VM '$vm_name' is up at $vm_ip"
    echo
    echo "Next:"
    echo "  1. sudo Bootstrap/scripts/init_testhosts.sh --ip $vm_ip"
    echo "  2. In JoyBox.ini, point a server entry at it and switch to local values:"
    echo "       [UserData.Servers]"
    echo "       domain_name = joybox.test"
    echo "       tls_mode = mkcert"
    echo "       server_0_host = $vm_ip"
    echo "       server_0_port = 22"
    echo "       server_0_user = $username"
    echo "       server_0_key_filepath = ${ssh_key_path%.pub}"
    echo "  3. ssh $username@$vm_ip     (console fallback: sudo virsh console $vm_name)"
}

snapshot_test_vm() {
    local vm_name="$1"
    local label="$2"
    echo "Taking snapshot '$label' of $vm_name..."
    virsh snapshot-create-as "$vm_name" "$label" --atomic
    echo "Revert with: sudo Bootstrap/scripts/testvm.sh revert $label"
}

revert_test_vm() {
    local vm_name="$1"
    local label="$2"
    echo "Reverting $vm_name to '$label'..."
    virsh snapshot-revert "$vm_name" "$label" --running
    echo "Reverted. The address may have changed - check with: sudo Bootstrap/scripts/testvm.sh ip"
}

destroy_test_vm() {
    local vm_name="$1"
    virsh destroy "$vm_name" 2>/dev/null || true
    virsh undefine "$vm_name" --remove-all-storage --snapshots-metadata 2>/dev/null || \
        virsh undefine "$vm_name" --remove-all-storage 2>/dev/null || true
    rm -f "$TESTVM_IMAGE_DIR/${vm_name}-seed.iso"
    echo "Destroyed $vm_name."
}

###########################################################
# Test domain resolution
#
# /etc/hosts rather than sslip.io or dnsmasq: the subdomain list is fixed and
# short, it needs no internet access, and it survives the VM's address changing
# across a snapshot revert with one re-run.
###########################################################

TESTHOSTS_MARKER_BEGIN="# BEGIN JoyBox local testing"
TESTHOSTS_MARKER_END="# END JoyBox local testing"

# Keep in step with the *_subdomain defaults in Shared/joybox/default_settings.py
TESTHOSTS_SUBDOMAINS=(www admin cloud tools tasks audio music aim)

remove_test_hosts() {
    if grep -qF "$TESTHOSTS_MARKER_BEGIN" /etc/hosts; then
        echo "Removing the existing JoyBox block from /etc/hosts..."
        sed -i "/^${TESTHOSTS_MARKER_BEGIN}$/,/^${TESTHOSTS_MARKER_END}$/d" /etc/hosts
    fi
}

configure_test_hosts() {
    local vm_ip="$1"
    local domain="${2:-joybox.test}"

    remove_test_hosts

    echo "Pointing $domain at $vm_ip..."
    {
        echo "$TESTHOSTS_MARKER_BEGIN"
        echo "$vm_ip $domain"
        local sub
        for sub in "${TESTHOSTS_SUBDOMAINS[@]}"; do
            echo "$vm_ip $sub.$domain"
        done
        echo "$TESTHOSTS_MARKER_END"
    } >> /etc/hosts

    echo "Done. Entries added:"
    echo "  $domain"
    local sub
    for sub in "${TESTHOSTS_SUBDOMAINS[@]}"; do
        echo "  $sub.$domain"
    done
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

###########################################################
# Hardening verification
#
# Every check asserts an effect rather than a configuration: a limit_req
# directive in "nginx -T" proves nothing if no request is ever refused, and a
# 127.0.0.1 line in a compose file proves nothing if the container published on
# 0.0.0.0 anyway.
#
# Runs on the target. Each check is callable on its own; verify_hardening runs
# the lot and leaves the failure count in VERIFY_FAILURES.
###########################################################

VERIFY_FAILURES=0

verify_pass() { echo "  PASS  $1"; }
verify_fail() { echo "  FAIL  $1"; VERIFY_FAILURES=$((VERIFY_FAILURES + 1)); }
verify_skip() { echo "  SKIP  $1"; }
verify_section() { echo; echo "== $1"; }

verify_container_ports() {
    verify_section "Container port bindings"

    if ! command -v docker &>/dev/null; then
        verify_skip "docker is not installed"
    else
        local exposed
        exposed="$(docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null | grep -E '0\.0\.0\.0|\[::\]' || true)"
        if [[ -z "$exposed" ]]; then
            verify_pass "no container publishes on 0.0.0.0"
        else
            verify_fail "containers published on all interfaces:"
            echo "$exposed" | sed 's/^/          /'
        fi
    fi

    # ss is the second opinion: it sees the actual listening socket, not
    # docker's view of what it asked for.
    if command -v ss &>/dev/null; then
        local wildcard
        wildcard="$(ss -tlnH 2>/dev/null | awk '{print $4}' \
            | grep -E '^(0\.0\.0\.0|\*|\[::\]):' | grep -vE ':(22|80|443)$' || true)"
        if [[ -z "$wildcard" ]]; then
            verify_pass "no unexpected wildcard listeners (only 22/80/443)"
        else
            verify_fail "unexpected wildcard listeners:"
            echo "$wildcard" | sed 's/^/          /'
        fi
    fi
}

verify_firewall() {
    verify_section "Firewall"

    if ! command -v ufw &>/dev/null; then
        verify_skip "ufw is not installed"
    elif ! ufw status 2>/dev/null | grep -q "Status: active"; then
        verify_fail "ufw is installed but not active"
    else
        verify_pass "ufw is active"
        echo "        allowed:"
        ufw status | awk '/ALLOW/ {print "          " $0}'
    fi
}

verify_sshd() {
    verify_section "sshd"

    if ! command -v sshd &>/dev/null; then
        verify_skip "sshd is not installed"
        return
    fi

    local effective
    effective="$(sshd -T 2>/dev/null || true)"
    if [[ -z "$effective" ]]; then
        verify_fail "could not read the effective sshd config"
        return
    fi

    if echo "$effective" | grep -qi "^passwordauthentication no"; then
        verify_pass "password authentication is disabled"
    else
        verify_fail "password authentication is still enabled"
    fi

    if echo "$effective" | grep -qiE "^permitrootlogin (no|prohibit-password)"; then
        verify_pass "root login is restricted"
    else
        verify_fail "root login is not restricted"
    fi
}

verify_fail2ban() {
    verify_section "fail2ban"

    if ! command -v fail2ban-client &>/dev/null; then
        verify_skip "fail2ban is not installed"
        return
    fi

    # The sshd jail silently matches nothing on Ubuntu 24.04+ unless it is told
    # to read journald, so assert it is actually running rather than configured.
    local jail
    for jail in sshd nginx-http-auth; do
        if fail2ban-client status "$jail" &>/dev/null; then
            verify_pass "jail '$jail' is running"
        else
            verify_fail "jail '$jail' is not running"
        fi
    done
}

verify_docker_hardening() {
    verify_section "Docker daemon"

    if [[ ! -f /etc/docker/daemon.json ]]; then
        verify_skip "no /etc/docker/daemon.json"
        return
    fi

    local key
    for key in userns-remap no-new-privileges; do
        if grep -q "$key" /etc/docker/daemon.json; then
            verify_pass "$key is configured"
        else
            verify_fail "$key is missing"
        fi
    done

    # Configured is not active: under userns-remap the daemon stores containers
    # under a root dir suffixed with the remapped uid.gid pair.
    if command -v docker &>/dev/null; then
        local remap
        remap="$(docker info --format '{{.DockerRootDir}}' 2>/dev/null | grep -oE '[0-9]+\.[0-9]+$' || true)"
        if [[ -n "$remap" ]]; then
            verify_pass "userns-remap is active (root dir suffix $remap)"
        else
            verify_fail "userns-remap does not appear active - DockerRootDir has no uid suffix"
        fi
    fi
}

verify_rate_limiting() {
    local domain="${1:-joybox.test}"
    verify_section "Rate limiting and headers"

    if ! command -v nginx &>/dev/null; then
        verify_skip "nginx is not installed"
        return
    fi

    local config
    config="$(nginx -T 2>/dev/null || true)"

    if echo "$config" | grep -q "limit_req_zone"; then
        verify_pass "limit_req_zone is defined"
    else
        verify_fail "limit_req_zone is missing"
    fi

    if echo "$config" | grep -qE "^\s*limit_req\s+zone="; then
        verify_pass "limit_req consumes the zone"
    else
        verify_fail "limit_req is missing - the zone is defined but never applied"
    fi

    if echo "$config" | grep -q "server_tokens off"; then
        verify_pass "server_tokens is off"
    else
        verify_fail "server_tokens is not off"
    fi

    # Burst past the configured rate and expect nginx to start refusing
    if command -v curl &>/dev/null; then
        local refused=0
        local attempt code
        for attempt in $(seq 1 40); do
            code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "https://$domain/" 2>/dev/null || echo 000)"
            if [[ "$code" == "503" ]]; then
                refused=$((refused + 1))
            fi
        done
        if [[ "$refused" -gt 0 ]]; then
            verify_pass "a 40-request burst was rate limited ($refused refused)"
        else
            verify_fail "a 40-request burst was never rate limited"
        fi
    fi
}

verify_unattended_upgrades() {
    verify_section "Unattended upgrades"

    if [[ ! -f /etc/apt/apt.conf.d/52-joybox-unattended ]]; then
        verify_fail "no /etc/apt/apt.conf.d/52-joybox-unattended"
        return
    fi

    verify_pass "JoyBox unattended-upgrades config is present"
    if grep -q 'Automatic-Reboot "true"' /etc/apt/apt.conf.d/52-joybox-unattended; then
        verify_pass "automatic reboot is enabled"
    else
        verify_fail "automatic reboot is not enabled - kernel updates install but never activate"
    fi
}

verify_hardening() {
    local domain="${1:-joybox.test}"
    VERIFY_FAILURES=0

    verify_container_ports
    verify_firewall
    verify_sshd
    verify_fail2ban
    verify_docker_hardening
    verify_rate_limiting "$domain"
    verify_unattended_upgrades

    echo
    if [[ "$VERIFY_FAILURES" -eq 0 ]]; then
        echo "All checks passed."
    else
        echo "$VERIFY_FAILURES check(s) failed."
    fi
    return "$VERIFY_FAILURES"
}
