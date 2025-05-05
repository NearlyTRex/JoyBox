# Server Initialization Script

- Installs a safe `/etc/sudoers.d/web-installer` rule using `visudo`
- Grants `apt-get` access only to a trusted list of packages
- Allows Nginx config file manipulation and reload
- Adds your user to the `docker` group for rootless Docker use

---

## Included Packages

Only the following packages can be managed with `apt-get`:

```

apache2-utils, apache2, certbot, curl, docker-compose, docker.io, git, nginx,
nginx-common, python3-certbot-nginx, unzip, wget

````

---

## Installation

### 1. Download the script

```bash
curl -O https://raw.githubusercontent.com/NearlyTRex/JoyBox/main/Bootstrap/initialize_server.sh
chmod +x initialize_server.sh
````

### 2. Run the script

Run it as `root`, passing the user that you want to use:

```bash
sudo ./initialize_server.sh yourusername
```

This will:

* Install the sudoers rule
* Add the user to the `docker` group

> **Note:** After running, the user may need to log out and back in for Docker group membership to take effect.

---

## Uninstall

To remove:

```bash
sudo rm /etc/sudoers.d/web-installer
sudo gpasswd -d yourusername docker
```
