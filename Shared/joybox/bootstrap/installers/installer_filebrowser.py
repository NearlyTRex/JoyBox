# Imports
import os
import sys

# Local imports
import joybox.bootstrap.constants as constants
from joybox import settings
from joybox import serverinfo
from . import installer_dockerapp
from joybox import runoptions
from joybox import logger

# Nginx config template
nginx_config_template = r"""
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
    listen 443 ssl;
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
services:
  filebrowser:
    image: ${FILEBROWSER_IMAGE}
    container_name: filebrowser
    restart: always
    ports:
      - "127.0.0.1:${FILEBROWSER_PORT_HTTP}:80"
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
class FileBrowser(installer_dockerapp.DockerAppInstaller):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.app_name = "filebrowser"
        self.nginx_config_values = {
            "domain": serverinfo.get_domain_name(),
            "subdomain": settings.get_value("UserData.FileBrowser", "filebrowser_subdomain"),
            "port_http": settings.get_value("UserData.FileBrowser", "filebrowser_port_http")
        }
        self.env_values = {
            "port_http": settings.get_value("UserData.FileBrowser", "filebrowser_port_http"),
            "user_root": settings.get_value("UserData.FileBrowser", "filebrowser_user_root"),
            "admin_user": settings.get_value("UserData.FileBrowser", "filebrowser_admin_user"),
            "admin_pass": settings.get_value("UserData.FileBrowser", "filebrowser_admin_pass")
        }

        # Templates
        self.docker_compose_template = docker_compose_template
        self.env_template = env_template
        self.nginx_config_template = nginx_config_template

        # Behavior
        self.required_settings = ["domain", "subdomain", "port_http", "user_root", "admin_user", "admin_pass"]

        # Backup
        self.backup_label = "FileBrowser"
        self.backup_volumes = ["config_data"]
