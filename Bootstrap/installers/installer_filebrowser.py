# Imports
import os
import sys

# Local imports
import util
from . import installer

# Nginx config template
nginx_config_template = """
server {{
    listen 80;
    server_name {subdomain}.{domain};

    # Only allow Let's Encrypt challenges on HTTP
    location /.well-known/acme-challenge/ {{
        root /var/www/html;
    }}

    # Redirect all other HTTP traffic to HTTPS
    location / {{
        return 301 https://{subdomain}.{domain}$request_uri;
    }}
}}

server {{
    listen 443 ssl http2;
    server_name {subdomain}.{domain};

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;

    # Include configurations
    include /etc/nginx/snippets/ssl-params.conf;

    # Main application location
    location / {{

        # HTTP Basic Authentication
        auth_basic "Secure Access Required";
        auth_basic_user_file /etc/nginx/.htpasswd;

        # Proxy configuration
        proxy_pass http://localhost:{port_http};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Host $server_name;
        proxy_set_header Cookie $http_cookie;

        # File upload and download optimization
        proxy_request_buffering off;
        proxy_buffering off;
        proxy_read_timeout 300s;
        proxy_connect_timeout 75s;

        # Support large file uploads (unlimited)
        client_max_body_size 0;
        client_body_timeout 300s;

        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }}

    # Static file serving with caching
    location ~* \.(css|js|ico|png|jpg|jpeg|gif|svg|woff|woff2|ttf|eot)$ {{
        proxy_pass http://localhost:{port_http};
        proxy_set_header Host $host;

        # Cache static assets
        expires 7d;
        add_header Cache-Control "public, no-transform";

        # Security headers for static content
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-Frame-Options "SAMEORIGIN" always;
    }}

    # Health check endpoint (no auth required)
    location = /health {{
        access_log off;
        proxy_pass http://localhost:{port_http}/health;
        proxy_set_header Host $host;
    }}
}}
"""

# Docker compose template
docker_compose_template = """
version: '3.8'
services:
  filebrowser:
    image: filebrowser/filebrowser
    container_name: filebrowser
    restart: always
    ports:
      - "${FILEBROWSER_PORT_HTTP}:80"
    volumes:
      - ${FILEBROWSER_ROOT}:/srv
      - config_data:/config
    entrypoint: >
      sh -c "
        if [ ! -f /config/filebrowser.db ]; then
          /filebrowser config init --database /config/filebrowser.db &&
          /filebrowser users add $FILEBROWSER_ADMIN_USER $FILEBROWSER_ADMIN_PASS --perm.admin --database /config/filebrowser.db;
        fi &&
        /filebrowser --database /config/filebrowser.db
      "
volumes:
  config_data: {}
"""

# .env template
env_template = """
FILEBROWSER_PORT_HTTP={port_http}
FILEBROWSER_ROOT={user_root}
FILEBROWSER_ADMIN_USER={admin_user}
FILEBROWSER_ADMIN_PASS={admin_pass}
"""

# FileBrowser Installer
class FileBrowser(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, connection, flags, options)
        self.app_name = "filebrowser"
        self.app_dir = f"$HOME/apps/{self.app_name}"
        self.nginx_config_values = {
            "domain": self.config.GetValue("UserData.Servers", "domain_name"),
            "subdomain": self.config.GetValue("UserData.FileBrowser", "filebrowser_subdomain"),
            "port_http": self.config.GetValue("UserData.FileBrowser", "filebrowser_port_http")
        }
        self.env_values = {
            "port_http": self.config.GetValue("UserData.FileBrowser", "filebrowser_port_http"),
            "user_root": self.config.GetValue("UserData.FileBrowser", "filebrowser_user_root"),
            "admin_user": self.config.GetValue("UserData.FileBrowser", "filebrowser_admin_user"),
            "admin_pass": self.config.GetValue("UserData.FileBrowser", "filebrowser_admin_pass")
        }

    def IsInstalled(self):
        containers = self.connection.RunOutput("docker ps -a --format '{{.Names}}'")
        return any(self.app_name in name for name in containers.splitlines())

    def Install(self):

        # Create directories
        util.LogInfo("Creating directories")
        self.connection.MakeDirectory(self.app_dir)

        # Write docker compose
        util.LogInfo("Writing docker compose")
        if self.connection.WriteFile("/tmp/docker-compose.yml", docker_compose_template):
            self.connection.MoveFileOrDirectory("/tmp/docker-compose.yml", f"{self.app_dir}/docker-compose.yml")

        # Write docker env
        util.LogInfo("Writing docker env")
        if self.connection.WriteFile("/tmp/.env", env_template.format(**self.env_values)):
            self.connection.MoveFileOrDirectory("/tmp/.env", f"{self.app_dir}/.env")

        # Create Nginx entry
        util.LogInfo("Creating Nginx entry")
        if self.connection.WriteFile(f"/tmp/{self.app_name}.conf", nginx_config_template.format(**self.nginx_config_values)):
            self.connection.RunChecked([self.nginx_manager_tool, "install_conf", f"/tmp/{self.app_name}.conf"], sudo = True)
            self.connection.RunChecked([self.nginx_manager_tool, "link_conf", f"{self.app_name}.conf"], sudo = True)
            self.connection.RemoveFileOrDirectory(f"/tmp/{self.app_name}.conf")

        # Restart Nginx
        util.LogInfo("Restarting Nginx")
        self.connection.RunChecked([self.nginx_manager_tool, "systemctl", "restart"], sudo = True)

        # Start docker
        util.LogInfo("Starting docker")
        self.connection.GetOptions().SetCurrentWorkingDirectory(self.app_dir)
        self.connection.RunChecked([self.docker_compose_tool, "--env-file", f"{self.app_dir}/.env", "up", "-d", "--build"])
        return True

    def Uninstall(self):

        # Stop docker
        util.LogInfo("Stopping docker")
        self.connection.GetOptions().SetCurrentWorkingDirectory(self.app_dir)
        self.connection.RunChecked([self.docker_compose_tool, "--env-file", f"{self.app_dir}/.env", "down", "-v"])
        self.connection.GetOptions().SetCurrentWorkingDirectory(None)

        # Remove directory
        util.LogInfo("Removing directory")
        self.connection.RemoveFileOrDirectory(self.app_dir)

        # Remove Nginx entry
        util.LogInfo("Removing Nginx entry")
        self.connection.RunChecked([self.nginx_manager_tool, "remove_conf", f"{self.app_name}.conf"], sudo = True)

        # Restart Nginx
        util.LogInfo("Restarting Nginx")
        self.connection.RunChecked([self.nginx_manager_tool, "systemctl", "restart"], sudo = True)
        return True
