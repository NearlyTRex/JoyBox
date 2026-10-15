# Imports
import base64
import binascii
import re

# Local imports
from joybox import settings
from joybox import serverinfo
from . import installer_dockerapp
from joybox import runoptions
from joybox import logger

# Nginx config template
#
# FileBrowser Quantum's own accounts are the login, so there is no basic auth.
# Its login throttling is keyed by client IP, read from X-Real-IP, which nginx
# always overwrites so a client cannot choose it.
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

    location / {{

        # Opening a folder fetches a thumbnail per file; the rate stays the same
        limit_req zone=mylimit burst={request_burst} nodelay;

        # Proxy configuration
        proxy_pass http://localhost:{port_http};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

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

    # Health check endpoint
    location = /health {{
        access_log off;
        proxy_pass http://localhost:{port_http}/health;
        proxy_set_header Host $host;
    }}
}}
"""

# Docker compose template
#
# The admin account is synced from JoyBox.ini on every start: created on the
# first, its password reset on the rest, so the ini stays the source of truth.
# Other accounts are managed in the app. Every account must add an
# authenticator code, whose seeds are stored encrypted with the TOTP secret. The config is inline so compose fills
# it from .env like the rest of the file.
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
      - data:/home/filebrowser/data
    environment:
      FILEBROWSER_CONFIG: /home/filebrowser/config.yaml
      FILEBROWSER_ADMIN_PASSWORD: ${FILEBROWSER_ADMIN_PASS}
      FILEBROWSER_TOTP_SECRET: ${FILEBROWSER_TOTP_SECRET}
    configs:
      - source: config
        target: /home/filebrowser/config.yaml
configs:
  config:
    content: |
      server:
        port: 80
        externalUrl: "https://${FILEBROWSER_HOST}"
        disableUpdateCheck: true
        sources:
          - path: /srv
            name: Storage
            config:
              defaultEnabled: true
      http:
        trustedHeaders:
          - X-Real-IP
      auth:
        adminUsername: "${FILEBROWSER_ADMIN_USER}"
        methods:
          password:
            enabled: true
            minLength: 12
            signup: false
            enforcedOtp: true
volumes:
  data: {}
"""

# .env template
env_template = """
FILEBROWSER_PORT_HTTP={port_http}
FILEBROWSER_ROOT={user_root}
FILEBROWSER_HOST={subdomain}.{domain}
FILEBROWSER_ADMIN_USER='{admin_user}'
FILEBROWSER_ADMIN_PASS='{admin_pass}'
FILEBROWSER_TOTP_SECRET='{totp_secret}'
"""

# Burst allowed past the shared rate limit
REQUEST_BURST = 100

# FileBrowser refuses shorter passwords
MINIMUM_ADMIN_PASS_LENGTH = 12

# Key sizes FileBrowser uses as given; anything else it stretches from a passphrase
TOTP_SECRET_SIZES = [16, 24, 32]

# What the admin name may hold; it lands inside a double-quoted YAML string
ADMIN_USER_PATTERN = re.compile(r"^[A-Za-z0-9._@-]+$")

# Check a TOTP secret is a base64 key of a size FileBrowser uses as given
def is_totp_secret(value):
    try:
        return len(base64.b64decode(str(value), validate = True)) in TOTP_SECRET_SIZES
    except binascii.Error:
        return False

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
            "port_http": settings.get_value("UserData.FileBrowser", "filebrowser_port_http"),
            "request_burst": REQUEST_BURST
        }
        self.env_values = {
            "domain": serverinfo.get_domain_name(),
            "subdomain": settings.get_value("UserData.FileBrowser", "filebrowser_subdomain"),
            "port_http": settings.get_value("UserData.FileBrowser", "filebrowser_port_http"),
            "user_root": settings.get_value("UserData.FileBrowser", "filebrowser_user_root"),
            "admin_user": settings.get_value("UserData.FileBrowser", "filebrowser_admin_user"),
            "admin_pass": settings.get_value("UserData.FileBrowser", "filebrowser_admin_pass"),
            "totp_secret": settings.get_value("UserData.FileBrowser", "filebrowser_totp_secret")
        }

        # Templates
        self.docker_compose_template = docker_compose_template
        self.env_template = env_template
        self.nginx_config_template = nginx_config_template

        # Behavior
        self.required_settings = ["domain", "subdomain", "port_http", "user_root", "admin_user", "admin_pass", "totp_secret"]
        self.quoted_settings = ["admin_user", "admin_pass", "totp_secret"]

        # Backup
        self.backup_label = "FileBrowser"
        self.backup_volumes = ["data"]

    def check_required_settings(self):
        if not super().check_required_settings():
            return False
        if not ADMIN_USER_PATTERN.match(str(self.env_values["admin_user"])):
            logger.log_error("filebrowser_admin_user may only hold letters, digits and . _ @ -")
            return False
        if len(str(self.env_values["admin_pass"])) < MINIMUM_ADMIN_PASS_LENGTH:
            logger.log_error(f"filebrowser_admin_pass must be at least {MINIMUM_ADMIN_PASS_LENGTH} characters")
            return False
        if not is_totp_secret(self.env_values["totp_secret"]):
            logger.log_error("filebrowser_totp_secret must be a key from: openssl rand -base64 32")
            return False
        return True
