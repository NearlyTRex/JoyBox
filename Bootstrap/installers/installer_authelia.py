# Imports
import os
import sys
import re

# Local imports
import util
from . import installer

# Nginx config template
nginx_config_template = """
server {{
    listen 80;
    server_name {subdomain}.{domain};
    return 301 https://$host$request_uri;
}}

server {{
    listen 443 ssl;
    server_name {subdomain}.{domain};

    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;

    location / {{
        proxy_pass http://localhost:{port_http};
        include proxy_params;
    }}
}}
"""

# Nginx Authelia location config template
nginx_auth_location_template = """
auth_request /authelia;
error_page 401 = @error401;

location = /authelia {{
    internal;
    proxy_pass http://localhost:{port_http}/api/verify;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Authorization $http_authorization;
}}
"""

# Nginx Authelia server config template
nginx_auth_server_template = """
error_page 401 = @error401;

location @error401 {{
    return 302 https://{subdomain}.{domain}/?rd=https://$host$request_uri;
}}
"""

# Docker compose template
docker_compose_template = """
version: '3.8'
services:
  authelia:
    image: authelia/authelia:latest
    container_name: authelia
    volumes:
      - ./config:/config
    ports:
      - "${AUTHELIA_PORT_HTTP}:${AUTHELIA_PORT_HTTP}"
    environment:
      AUTHELIA_SESSION_SECRET: ${AUTHELIA_SESSION_SECRET}
      AUTHELIA_STORAGE_ENCRYPTION_KEY: ${AUTHELIA_STORAGE_ENCRYPTION_KEY}
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:${AUTHELIA_PORT_HTTP}"]
      interval: 30s
      timeout: 10s
      retries: 3
    restart: unless-stopped
"""

# Env template
env_template = """
AUTHELIA_PORT_HTTP={port_http}
AUTHELIA_JWT_SECRET={jwt_secret}
AUTHELIA_SESSION_SECRET={session_secret}
AUTHELIA_STORAGE_ENCRYPTION_KEY={storage_key}
"""

# Configuration template
configuration_template = """
identity_validation:
  reset_password:
    jwt_secret: {jwt_secret}

server:
  address: tcp://0.0.0.0:{port_http}

log:
  level: info

totp:
  issuer: {domain}
  period: 30
  skew: 1

authentication_backend:
  password_reset:
    disable: false
  refresh_interval: 5m
  file:
    path: /config/users_database.yml
    password:
      algorithm: argon2id
      iterations: 1
      key_length: 32
      salt_length: 16
      memory: 1024
      parallelism: 8

access_control:
  default_policy: deny
  rules:
    - domain:
        - "{subdomain}.{domain}"
      policy: bypass
    - domain:
        - "*.{domain}"
      subject:
        - "group:admins"
      policy: two_factor

session:
  name: authelia_session
  secret: "{session_secret}"
  expiration: 1h
  inactivity: 5m
  remember_me: 1M
  same_site: lax
  cookies:
    - domain: {domain}
      authelia_url: https://{subdomain}.{domain}
      default_redirection_url: https://{domain}

regulation:
  max_retries: 3
  find_time: 10m
  ban_time: 12h

storage:
  encryption_key: "{storage_key}"
  local:
    path: /config/db.sqlite3

notifier:
  filesystem:
    filename: /config/notification.txt
# """

# Users database template
users_database_template = """
users:
  {admin_username}:
    displayname: "{admin_displayname}"
    password: {admin_password_hash}
    email: {admin_email}
    groups:
      - admins
"""

# Authelia
class Authelia(installer.Installer):
    def __init__(
        self,
        config,
        connection,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        super().__init__(config, connection, flags, options)
        self.app_name = "authelia"
        self.app_dir = f"$HOME/apps/{self.app_name}"
        self.nginx_config_values = {
            "domain": self.config.GetValue("UserData.Servers", "domain_name"),
            "subdomain": self.config.GetValue("UserData.Authelia", "authelia_subdomain"),
            "port_http": self.config.GetValue("UserData.Authelia", "authelia_port_http")
        }
        self.nginx_authelia_location_config_values = {
            "port_http": self.config.GetValue("UserData.Authelia", "authelia_port_http")
        }
        self.nginx_authelia_server_config_values = {
            "domain": self.config.GetValue("UserData.Servers", "domain_name"),
            "subdomain": self.config.GetValue("UserData.Authelia", "authelia_subdomain")
        }
        self.env_values = {
            "port_http": self.config.GetValue("UserData.Authelia", "authelia_port_http"),
            "jwt_secret": self.config.GetValue("UserData.Authelia", "authelia_jwt_secret"),
            "session_secret": self.config.GetValue("UserData.Authelia", "authelia_session_secret"),
            "storage_key": self.config.GetValue("UserData.Authelia", "authelia_storage_encryption_key")
        }
        self.configuration_values = {
            "domain": self.config.GetValue("UserData.Servers", "domain_name"),
            "subdomain": self.config.GetValue("UserData.Authelia", "authelia_subdomain"),
            "port_http": self.config.GetValue("UserData.Authelia", "authelia_port_http"),
            "session_secret": self.config.GetValue("UserData.Authelia", "authelia_session_secret"),
            "jwt_secret": self.config.GetValue("UserData.Authelia", "authelia_jwt_secret"),
            "storage_key": self.config.GetValue("UserData.Authelia", "authelia_storage_encryption_key")
        }
        self.users_database_values = {
            "admin_username": self.config.GetValue("UserData.Authelia", "authelia_admin_username"),
            "admin_displayname": self.config.GetValue("UserData.Authelia", "authelia_admin_displayname"),
            "admin_email": self.config.GetValue("UserData.Authelia", "authelia_admin_email"),
            "admin_password_hash": self.GeneratePasswordHash(
                self.config.GetValue("UserData.Authelia", "authelia_admin_password"))
        }
        if not self.users_database_values.get("admin_password_hash"):
            raise Exception("Unable to generate password hash")

    def IsInstalled(self):
        containers = self.connection.RunOutput("docker ps -a --format '{{.Names}}'")
        return any(self.app_name in name for name in containers.splitlines())

    def Install(self):

        # Create directories
        util.LogInfo("Making directories")
        self.connection.MakeDirectory(self.app_dir)
        self.connection.MakeDirectory(f"{self.app_dir}/config")

        # Write docker compose
        util.LogInfo("Writing docker compose")
        if self.connection.WriteFile("/tmp/docker-compose.yml", docker_compose_template):
            self.connection.MoveFileOrDirectory("/tmp/docker-compose.yml", f"{self.app_dir}/docker-compose.yml")

        # Write docker env
        util.LogInfo("Writing docker env")
        if self.connection.WriteFile(f"/tmp/.env", env_template.format(**self.env_values)):
            self.connection.MoveFileOrDirectory("/tmp/.env", f"{self.app_dir}/.env")

        # Write configuration
        util.LogInfo("Writing configuration")
        if self.connection.WriteFile("/tmp/configuration.yml", configuration_template.format(**self.configuration_values)):
            self.connection.MoveFileOrDirectory("/tmp/configuration.yml", f"{self.app_dir}/config/configuration.yml")

        # Write users database
        util.LogInfo("Writing users database")
        if self.connection.WriteFile("/tmp/users_database.yml", users_database_template.format(**self.users_database_values)):
            self.connection.MoveFileOrDirectory("/tmp/users_database.yml", f"{self.app_dir}/config/users_database.yml")

        # Create Nginx entry
        util.LogInfo("Creating Nginx entry")
        if self.connection.WriteFile(f"/tmp/{self.app_name}.conf", nginx_config_template.format(**self.nginx_config_values)):
            self.connection.RunChecked([self.nginx_manager_tool, "install_conf", f"/tmp/{self.app_name}.conf"], sudo = True)
            self.connection.RunChecked([self.nginx_manager_tool, "link_conf", f"{self.app_name}.conf"], sudo = True)
            self.connection.RemoveFileOrDirectory(f"/tmp/{self.app_name}.conf")

        # Create Nginx auth location config
        util.LogInfo("Creating Nginx auth location config")
        if self.connection.WriteFile(f"/tmp/auth_location.conf", nginx_auth_location_template.format(**self.nginx_authelia_location_config_values)):
            self.connection.RunChecked([self.nginx_manager_tool, "install_authelia_conf", f"/tmp/auth_location.conf"], sudo = True)
            self.connection.RemoveFileOrDirectory(f"/tmp/auth_location.conf")

        # Create Nginx auth server config
        util.LogInfo("Creating Nginx auth server config")
        if self.connection.WriteFile(f"/tmp/auth_server.conf", nginx_auth_server_template.format(**self.nginx_authelia_server_config_values)):
            self.connection.RunChecked([self.nginx_manager_tool, "install_authelia_conf", f"/tmp/auth_server.conf"], sudo = True)
            self.connection.RemoveFileOrDirectory(f"/tmp/auth_server.conf")

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

        # Remove directory
        util.LogInfo("Removing directory")
        self.connection.RemoveFileOrDirectory(self.app_dir)

        # Remove Nginx auth entries
        util.LogInfo("Removing Nginx auth entries")
        self.connection.RunChecked([self.nginx_manager_tool, "remove_authelia_conf", "auth_location.conf"], sudo = True)
        self.connection.RunChecked([self.nginx_manager_tool, "remove_authelia_conf", "auth_server.conf"], sudo = True)

        # Remove Nginx entry
        util.LogInfo("Removing Nginx entry")
        self.connection.RunChecked([self.nginx_manager_tool, "remove_conf", f"{self.app_name}.conf"], sudo = True)

        # Restart Nginx
        util.LogInfo("Restarting Nginx")
        self.connection.RunChecked([self.nginx_manager_tool, "systemctl", "restart"], sudo = True)
        return True

    def GeneratePasswordHash(self, password):

        # Generate password hash
        result = self.connection.RunOutput([
            self.docker_tool,
            "run",
            "--rm",
            "authelia/authelia:latest",
            "authelia",
            "crypto", "hash",
            "generate", "argon2",
            "--password", password
        ])

        # Search for password hash
        match = re.search(r'\$argon2id\$[^\s]+', result.strip())
        if match:
            return match.group(0)
        return None
