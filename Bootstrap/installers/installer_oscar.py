# Imports
import os
import sys

# Local imports
import constants
from joybox import settings
from . import installer_dockerapp
from joybox import runoptions
from joybox import logger

# Nginx stream config template
#
# The container binds to loopback only and nginx publishes the port. Docker's
# published ports bypass ufw entirely, so binding the container publicly would
# put port 5190 on the internet regardless of the firewall. Going through nginx
# is what makes ufw actually govern this port.
nginx_stream_config_template = """
upstream oscar_bos {{
    server 127.0.0.1:{port_bos};
}}

server {{
    listen {port_public};
    proxy_pass oscar_bos;

    # OSCAR sessions stay open for as long as the user is signed in, so the
    # short timeouts used for request/response protocols would drop clients.
    proxy_timeout 1h;
    proxy_connect_timeout 10s;

    error_log /var/log/nginx/oscar_bos.log;
}}
"""

# Nginx config template
#
# The management API is how screen names get created, so it is proxied over
# https behind the shared htpasswd file rather than exposed directly.
nginx_config_template = """
server {{
    listen 80;
    server_name {subdomain}.{domain};

    location / {{
        return 301 https://{subdomain}.{domain}$request_uri;
    }}
}}

server {{
    listen 443 ssl;
    server_name {subdomain}.{domain};

    # SSL configuration
    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;

    # Shared TLS policy and security headers
    include /etc/nginx/snippets/ssl-params.conf;

    location / {{

        # HTTP Basic Authentication
        auth_basic "Secure Access Required";
        auth_basic_user_file /etc/nginx/.htpasswd;

        # Proxy configuration
        proxy_pass http://localhost:{port_api};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }}
}}
"""

# Dockerfile template
#
# Upstream publishes no container image, so the server is built from a pinned
# git tag. The sqlite driver is pure Go (modernc.org/sqlite), so the binary can
# be built without cgo and shipped on a bare runtime image.
dockerfile_template = """
ARG OSCAR_BUILDER_IMAGE=golang:1.26.2-alpine
ARG OSCAR_RUNTIME_IMAGE=alpine:3.22

FROM ${OSCAR_BUILDER_IMAGE} AS builder
ARG OSCAR_VERSION
RUN apk add --no-cache git
WORKDIR /src
RUN git clone --depth 1 --branch ${OSCAR_VERSION} https://github.com/mk6i/open-oscar-server.git .
RUN CGO_ENABLED=0 go build -trimpath -o open_oscar_server ./cmd/server

FROM ${OSCAR_RUNTIME_IMAGE}
RUN adduser -D -u 10000 oscar && mkdir -p /data && chown oscar:oscar /data
WORKDIR /app
COPY --from=builder /src/open_oscar_server /app/open_oscar_server
USER oscar
EXPOSE 5190 8080
CMD ["/app/open_oscar_server"]
"""

# Docker compose template
docker_compose_template = """
services:
  oscar:
    build:
      context: .
      dockerfile: Dockerfile
      args:
        OSCAR_BUILDER_IMAGE: ${OSCAR_BUILDER_IMAGE}
        OSCAR_RUNTIME_IMAGE: ${OSCAR_RUNTIME_IMAGE}
        OSCAR_VERSION: ${OSCAR_VERSION}
    container_name: oscar
    restart: always
    ports:
      - "127.0.0.1:${OSCAR_PORT_BOS}:5190"
      - "127.0.0.1:${OSCAR_PORT_API}:8080"
    volumes:
      - oscar_data:/data
    environment:
      # Bind inside the container; nginx owns the public port.
      OSCAR_LISTENERS: WAN://0.0.0.0:5190

      # The hostname clients are redirected to after auth. This must be
      # reachable from the internet or sign-in succeeds and then hangs.
      OSCAR_ADVERTISED_LISTENERS_PLAIN: WAN://${OSCAR_PUBLIC_HOST}:${OSCAR_PORT_PUBLIC}

      # Required by the server, but bound to loopback so it is not reachable.
      TOC_LISTENERS: 127.0.0.1:9898

      # Container-internal; published to host loopback and proxied by nginx.
      API_LISTENER: 0.0.0.0:8080

      # Unused protocols
      WEBAPI_LISTENERS: ""
      ICQ_LEGACY_ENABLED: "false"

      DB_PATH: /data/oscar.sqlite

      # Screen names are created through the management API. With this true,
      # anyone who reaches the port claims any name, password unchecked.
      DISABLE_AUTH: "false"

      DISABLE_MULTI_LOGIN_NOTIF: "false"
      LOG_LEVEL: ${OSCAR_LOG_LEVEL}
    healthcheck:
      test: ["CMD", "nc", "-z", "127.0.0.1", "5190"]
      interval: 30s
      timeout: 5s
      retries: 5

volumes:
  oscar_data:
"""

# Env template
env_template = """
OSCAR_PUBLIC_HOST={public_host}
OSCAR_PORT_PUBLIC={port_public}
OSCAR_PORT_BOS={port_bos}
OSCAR_PORT_API={port_api}
OSCAR_LOG_LEVEL={log_level}
"""

# Oscar
class Oscar(installer_dockerapp.DockerAppInstaller):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.app_name = "oscar"
        self.domain_name = settings.get_value("UserData.Servers", "domain_name")
        self.subdomain = settings.get_value("UserData.Oscar", "oscar_subdomain",
            default_value = "aim", throw_exception = False)
        self.port_public = settings.get_value("UserData.Oscar", "oscar_port_public",
            default_value = "5190", throw_exception = False)
        self.nginx_config_values = {
            "domain": self.domain_name,
            "subdomain": self.subdomain,
            "port_public": self.port_public,
            "port_bos": settings.get_value("UserData.Oscar", "oscar_port_bos",
                default_value = "15190", throw_exception = False),
            "port_api": settings.get_value("UserData.Oscar", "oscar_port_api",
                default_value = "18080", throw_exception = False)
        }
        self.env_values = {
            "public_host": f"{self.subdomain}.{self.domain_name}",
            "port_public": self.port_public,
            "port_bos": self.nginx_config_values["port_bos"],
            "port_api": self.nginx_config_values["port_api"],
            "log_level": settings.get_value("UserData.Oscar", "oscar_log_level",
                default_value = "info", throw_exception = False)
        }

        # Templates
        self.docker_compose_template = docker_compose_template
        self.env_template = env_template
        self.nginx_config_template = nginx_config_template

        # Behavior
        self.nginx_ports = [str(self.port_public)]
        self.required_settings = ["domain", "subdomain", "port_public", "port_bos", "port_api"]

        # Backup
        # A single SQLite file holding accounts, buddy lists and offline messages.
        self.backup_label = "Oscar"
        self.backup_volumes = ["oscar_data"]

    def install(self):

        # Write the Dockerfile before the base class runs compose build
        logger.log_info("Writing dockerfile")
        app_dir = self.get_app_dir()
        self.connection.make_directory(app_dir)
        dockerfile_tmp_path = f"/tmp/{self.app_name}.Dockerfile"
        if not self.connection.write_file(dockerfile_tmp_path, dockerfile_template):
            logger.log_error(f"Unable to write dockerfile for {self.app_name}")
            return False
        self.connection.move_file_or_directory(dockerfile_tmp_path, f"{app_dir}/Dockerfile")
        return super().install()

    def install_nginx_config(self):

        # Public OSCAR port, proxied to the loopback-bound container
        logger.log_info("Installing Oscar stream entry")
        stream_tmp_path = f"/tmp/{self.app_name}.stream.conf"
        if self.connection.write_file(stream_tmp_path,
                nginx_stream_config_template.format(**self.nginx_config_values)):
            self.connection.run_checked([self.nginx_manager_tool, "install_stream_conf", stream_tmp_path], sudo = True)
            self.connection.run_checked([self.nginx_manager_tool, "link_stream_conf", f"{self.app_name}.stream.conf"], sudo = True)
            self.connection.remove_file_or_directory(stream_tmp_path)

        # Management API vhost
        logger.log_info("Installing Oscar API entry")
        return super().install_nginx_config()

    def uninstall_nginx_config(self):

        # Remove the stream entry
        logger.log_info("Removing Oscar stream entry")
        self.connection.run_checked([self.nginx_manager_tool, "remove_stream_conf", f"{self.app_name}.stream.conf"], sudo = True)

        # Remove the API vhost
        logger.log_info("Removing Oscar API entry")
        return super().uninstall_nginx_config()
