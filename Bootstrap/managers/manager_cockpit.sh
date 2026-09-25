#!/bin/bash

set -euo pipefail

install_cockpit() {

    apt-get update
    apt-get install -y network-manager
    apt-get install -y cockpit cockpit-networkmanager cockpit-packagekit cockpit-storaged cockpit-system

    if ! systemctl enable --now NetworkManager; then
        echo "Error: Failed to enable and start NetworkManager."
        exit 1
    fi

    if ! systemctl enable --now cockpit.socket; then
        echo "Error: Failed to enable and start cockpit.socket."
        exit 1
    fi

    if command -v ufw >/dev/null && ufw status | grep -q active; then
        ufw allow 9090/tcp
    fi

    if grep -q '^ *renderer:' /etc/netplan/*.yaml 2>/dev/null; then
        sed -i 's/renderer: .*/renderer: NetworkManager/' /etc/netplan/*.yaml
    else
        echo -e "network:\n  version: 2\n  renderer: NetworkManager" > /etc/netplan/99-cockpit.yaml
    fi

    if ! netplan apply; then
        echo "Netplan failed — check your configuration."
        exit 1
    fi

    cat > "/etc/polkit-1/rules.d/50-cockpit-packagekit.rules" <<EOF
polkit.addRule(function(action, subject) {
    if ((action.id == "org.freedesktop.packagekit.system-sources-refresh" ||
         action.id == "org.freedesktop.packagekit.system-update") &&
        subject.isInGroup("sudo")) {
        return polkit.Result.YES;
    }
});
EOF

    cat > "/etc/polkit-1/localauthority/50-local.d/45-allow-cockpit.pkla" <<EOF
[Allow Admin Cockpit Access]
Identity=unix-group:sudo
Action=*
ResultActive=yes
EOF
}

uninstall_cockpit() {

    systemctl disable --now cockpit.socket || true
    systemctl disable --now NetworkManager || true

    apt-get remove --purge -y network-manager || true
    apt-get remove --purge -y cockpit cockpit-networkmanager cockpit-packagekit cockpit-storaged cockpit-system || true
    apt-get autoremove -y
    apt-get clean

    if command -v ufw >/dev/null && ufw status | grep -q active; then
        yes | ufw delete allow 9090/tcp 2>/dev/null || echo "Firewall rule may not have existed."
    fi

    if [ -f /etc/netplan/99-cockpit.yaml ]; then
        rm -f /etc/netplan/99-cockpit.yaml
        netplan apply
    fi

    rm -f /etc/polkit-1/rules.d/50-cockpit-packagekit.rules
    rm -f /etc/polkit-1/localauthority/50-local.d/45-allow-cockpit.pkla
}

print_usage() {
    echo "Usage:"
    echo "  $0 install"
    echo "  $0 uninstall"
    exit 1
}

if [ $# -ne 1 ]; then
    print_usage
fi

case "$1" in
    install)
        install_cockpit
        ;;
    uninstall)
        uninstall_cockpit
        ;;
    *)
        echo "Error: Invalid command '$1'."
        print_usage
        ;;
esac
