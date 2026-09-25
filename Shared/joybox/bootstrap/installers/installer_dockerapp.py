# Imports
import os
import sys

# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.packages as packages
from joybox import settings
from . import installer
from joybox import runoptions
from joybox import logger

# Nginx http config template
nginx_http_config_template = """
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
        proxy_pass http://localhost:{port_http};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Cookie $http_cookie;
    }}
}}
"""

# Nginx http websocket config template
nginx_http_websocket_config_template = """
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
        proxy_pass http://localhost:{port_http};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Cookie $http_cookie;
    }}
}}
"""

# Docker app installer
#
# Shared skeleton for the Docker Compose apps. A subclass sets its app name,
# its compose/env/nginx templates and the values they format with; everything
# else - directories, temp file staging, nginx wiring, compose lifecycle - is
# handled here.
class DockerAppInstaller(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)

        # App identity
        self.app_name = "dockerapp"
        self.app_subdirs = []

        # Templates
        self.docker_compose_template = ""
        self.env_template = ""
        self.nginx_config_template = nginx_http_config_template

        # Template values
        self.env_values = {}
        self.nginx_config_values = {}

        # Behavior
        self.nginx_config_mode = "http"
        self.nginx_ports = []
        self.required_settings = []

        # Backup
        self.backup_label = ""
        self.backup_database = ""
        self.backup_volumes = []
        self.backup_dirs = []
        self.backup_excludes = []

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.REMOTE_UBUNTU,
        ]

    def is_installed(self):
        containers = self.connection.run_output("docker ps -a --format '{{.Names}}'")
        return any(self.app_name in name for name in containers.splitlines())

    def get_app_images(self):

        # Central pins from packages/images.py, optionally overridden
        # per-server by the same name lowercased under [UserData.Images].
        images = {}
        for env_name, pinned_image in packages.docker_images.get(self.app_name, {}).items():
            override = settings.get_value("UserData.Images", env_name.lower(),
                default_value = "", throw_exception = False)
            if override and override.strip():
                images[env_name] = override.strip()
            else:
                images[env_name] = pinned_image
        return images

    def get_image_env_lines(self):

        # Compose substitutes ${VAR} from the env file, so pins reach the
        # compose template through .env rather than Python formatting.
        lines = ""
        for env_name, image_ref in self.get_app_images().items():
            lines += f"{env_name}={image_ref}\n"
        return lines

    def get_nginx_action(self, action):
        if self.nginx_config_mode == "stream":
            return f"{action}_stream_conf"
        return f"{action}_conf"

    def check_required_settings(self):

        # A missing key resolves to None and formats into templates as the
        # string "None", producing a config that looks valid and is not.
        values = dict(self.env_values)
        values.update(self.nginx_config_values)
        missing = [key for key in self.required_settings
            if values.get(key) is None or str(values.get(key)).strip() in ["", "None"]]
        if missing:
            logger.log_error(f"Missing required settings for {self.app_name}: {', '.join(missing)}")
            logger.log_error(f"Set them in {settings.get_settings_file()} and re-run")
            return False
        return True

    def get_backup_root(self):
        return settings.get_value("UserData.Backup", "backup_root",
            default_value = "/mnt/storage/Backups", throw_exception = False)

    def get_backup_keep(self):
        keep = settings.get_value("UserData.Backup", "backup_keep",
            default_value = "7", throw_exception = False)
        try:
            return max(1, int(str(keep).strip()))
        except ValueError:
            return 7

    def get_backup_age_recipient(self):
        return settings.get_value("UserData.Backup", "backup_age_recipient",
            default_value = "", throw_exception = False).strip()

    def get_backup_age_identity(self):
        return settings.get_value("UserData.Backup", "backup_age_identity",
            default_value = "", throw_exception = False).strip()

    def get_backup_label(self):
        return self.backup_label if self.backup_label else self.app_name

    def get_backup_dir(self):
        return "%s/%s" % (self.get_backup_root(), self.get_backup_label())

    def has_backup_items(self):
        return bool(self.backup_database or self.backup_volumes or self.backup_dirs)

    def get_helper_image(self):
        return settings.get_value("UserData.Images", "backup_helper_image",
            default_value = "", throw_exception = False).strip() \
            or packages.docker_images["_backup"]["BACKUP_HELPER_IMAGE"]

    def get_container_lookup(self, service):

        # Resolve by compose label rather than container name: the services do
        # not set container_name, so the real name is <project>-<service>-1.
        return ("docker ps -q --filter label=com.docker.compose.project=%s "
                "--filter label=com.docker.compose.service=%s | head -n1") % (self.app_name, service)

    def get_backup_preamble(self):

        # A silent backup onto an unmounted path fills the root disk instead.
        return """set -euo pipefail
BACKUP_BASE=%s
ls "$BACKUP_BASE" >/dev/null 2>&1 || true
if ! mountpoint -q "$(dirname "$BACKUP_BASE")" 2>/dev/null; then
    echo "Warning: $(dirname "$BACKUP_BASE") is not a mount point"
fi
mkdir -p "$BACKUP_BASE"
if [ ! -w "$BACKUP_BASE" ]; then
    echo "Error: $BACKUP_BASE is not writable"
    exit 1
fi
""" % self.get_backup_dir()

    def build_backup_script(self, tag = ""):

        # Everything is redirected server-side; archive bytes never travel
        # back through the SSH channel.
        suffix = ("_" + tag) if tag else ""
        recipient = self.get_backup_age_recipient()

        # Archives carry downstream secrets - database dumps, password hashes,
        # account stores - and land on third-party storage. Encrypting to a public
        # key means the server cannot read back what it wrote.
        enc = ('| age -r %s ' % recipient) if recipient else ""
        ext = ".age" if recipient else ""

        script = self.get_backup_preamble()
        if recipient:
            script += ('command -v age >/dev/null 2>&1 || '
                       '{ echo "Error: backup_age_recipient is set but age is not installed"; exit 1; }\n')
        script += 'STAMP="$(date -u +%Y%m%d_%H%M%S)' + suffix + '"\n'
        script += 'DEST="$BACKUP_BASE/$STAMP.partial"\n'
        script += 'mkdir -p "$DEST"\n'
        script += 'echo "# JoyBox backup" > "$DEST/backup_manifest.txt"\n'
        script += 'echo "# App: %s" >> "$DEST/backup_manifest.txt"\n' % self.get_backup_label()
        script += 'echo "# Project: %s" >> "$DEST/backup_manifest.txt"\n' % self.app_name
        script += 'echo "# Created: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$DEST/backup_manifest.txt"\n'
        script += 'echo "# Host: $(hostname)" >> "$DEST/backup_manifest.txt"\n'

        # Backup databases
        if self.backup_database:
            script += 'CID="$(%s)"\n' % self.get_container_lookup(self.backup_database)
            script += 'if [ -z "$CID" ]; then echo "Error: database container for %s is not running"; exit 1; fi\n' % self.app_name
            script += ('docker exec "$CID" sh -c \'command -v mariadb-dump >/dev/null 2>&1 && D=mariadb-dump || D=mysqldump; '
                       'exec "$D" --single-transaction --quick --routines --triggers --default-character-set=utf8mb4 '
                       '-u root -p"${MYSQL_ROOT_PASSWORD:-$MARIADB_ROOT_PASSWORD}" '
                       '"${MYSQL_DATABASE:-$MARIADB_DATABASE}"\' | gzip -9 %s> "$DEST/db.sql.gz%s"\n') % (enc, ext)
            script += 'echo "db.sql.gz%s\tdatabase\t%s" >> "$DEST/backup_manifest.txt"\n' % (ext, self.backup_database)
        excludes = " ".join(['--exclude=%s' % e for e in self.backup_excludes])
        for volume in self.backup_volumes:
            full_volume = "%s_%s" % (self.app_name, volume)
            script += ('docker run --rm -v %s:/src:ro %s tar -C /src %s -cf - . '
                       '| gzip -9 %s> "$DEST/%s.tar.gz%s"\n') % (full_volume, self.get_helper_image(), excludes, enc, volume, ext)
            script += 'echo "%s.tar.gz%s\tvolume\t%s" >> "$DEST/backup_manifest.txt"\n' % (volume, ext, full_volume)
        for directory in self.backup_dirs:
            host_path = "%s/%s" % (self.get_app_dir(), directory)
            script += ('docker run --rm -v %s:/src:ro %s tar -C /src %s -cf - . '
                       '| gzip -9 %s> "$DEST/%s.tar.gz%s"\n') % (host_path, self.get_helper_image(), excludes, enc, directory, ext)
            script += 'echo "%s.tar.gz%s\tdirectory\t%s" >> "$DEST/backup_manifest.txt"\n' % (directory, ext, host_path)

        # Checksums, then publish atomically so a partial write is never
        # mistaken for a finished backup.
        script += ('cd "$DEST" && find . -maxdepth 1 -type f \\( -name "*.gz" -o -name "*.age" \\) '
                   '-printf "%P\\n" | sort | xargs -r sha256sum > SHA256SUMS\n')
        script += 'mv "$DEST" "$BACKUP_BASE/$STAMP"\n'
        script += 'ln -sfn "$BACKUP_BASE/$STAMP" "$BACKUP_BASE/latest" || echo "Warning: could not update latest symlink"\n'
        script += 'echo "Backup complete: $BACKUP_BASE/$STAMP"\n'

        # Retention
        script += ('{ ls -1d "$BACKUP_BASE"/*/ 2>/dev/null || true; } | grep -v "\\.partial/$" '
                   '| sort | head -n -%d | xargs -r rm -rf || true\n') % self.get_backup_keep()
        script += 'rm -rf "$BACKUP_BASE"/*.partial 2>/dev/null || true\n'
        return script

    def backup(self, tag = ""):

        # Nothing stateful to capture
        if not self.has_backup_items():
            return True
        if not self.is_installed():
            logger.log_info(f"Skipping backup of {self.app_name} - not installed")
            return True

        # Run backup
        logger.log_info(f"Backing up {self.app_name} to {self.get_backup_dir()}")
        code = self.connection.run_blocking(["bash", "-c", self.build_backup_script(tag)])
        if code != 0:
            logger.log_error(f"Backup of {self.app_name} failed (exit {code})")
            return False
        return True

    def build_restore_script(self, backup_id, identity_path = ""):
        script = self.get_backup_preamble()
        if identity_path:
            script += 'AGE_IDENTITY=%s\n' % identity_path
        script += """archive_stream() {
    # $1 is the plain archive name; prefer its encrypted sibling when present so
    # backups taken before encryption was enabled still restore unchanged.
    if [ -f "$SRC/$1.age" ]; then
        if [ -z "${AGE_IDENTITY:-}" ]; then
            echo "Error: $1.age is encrypted but backup_age_identity is not set" >&2
            exit 1
        fi
        age -d -i "$AGE_IDENTITY" "$SRC/$1.age" | gzip -dc
    elif [ -f "$SRC/$1" ]; then
        gzip -dc "$SRC/$1"
    else
        echo "Error: neither $1 nor $1.age found in $SRC" >&2
        exit 1
    fi
}
"""
        script += 'SRC="$BACKUP_BASE/%s"\n' % backup_id
        script += 'if [ ! -d "$SRC" ]; then echo "Error: no backup at $SRC"; exit 1; fi\n'
        script += 'echo "Restoring from $SRC"\n'
        script += 'cd "$SRC" && sha256sum -c SHA256SUMS\n'
        for volume in self.backup_volumes:
            full_volume = "%s_%s" % (self.app_name, volume)
            script += ('archive_stream "%s.tar.gz" | docker run --rm -i -v %s:/dst %s '
                       'sh -c \'rm -rf /dst/..?* /dst/.[!.]* /dst/* 2>/dev/null; exec tar -C /dst -xf -\'\n') % (
                       volume, full_volume, self.get_helper_image())
        for directory in self.backup_dirs:
            host_path = "%s/%s" % (self.get_app_dir(), directory)
            script += ('archive_stream "%s.tar.gz" | docker run --rm -i -v %s:/dst %s '
                       'sh -c \'rm -rf /dst/..?* /dst/.[!.]* /dst/* 2>/dev/null; exec tar -C /dst -xf -\'\n') % (
                       directory, host_path, self.get_helper_image())
        if self.backup_database:
            script += 'CID="$(%s)"\n' % self.get_container_lookup(self.backup_database)
            script += 'if [ -z "$CID" ]; then echo "Error: database container for %s is not running"; exit 1; fi\n' % self.app_name
            script += ('archive_stream "db.sql.gz" | docker exec -i "$CID" sh -c '
                       '\'command -v mariadb >/dev/null 2>&1 && M=mariadb || M=mysql; '
                       'exec "$M" -u root -p"${MYSQL_ROOT_PASSWORD:-$MARIADB_ROOT_PASSWORD}" '
                       '"${MYSQL_DATABASE:-$MARIADB_DATABASE}"\'\n')
        script += 'echo "Restore complete from $SRC"\n'
        return script

    def restore(self):

        # Nothing stateful to restore
        if not self.has_backup_items():
            return True
        if not self.is_installed():
            logger.log_error(f"{self.app_name} is not installed; install it before restoring")
            return False

        # Resolve which backup to restore
        backup_id = self.flags.backup_id if self.flags.backup_id else "latest"

        # Snapshot current state first so the restore itself is undoable
        logger.log_info(f"Taking pre-restore snapshot of {self.app_name}")
        if not self.backup(tag = "prerestore"):
            logger.log_error("Pre-restore snapshot failed; aborting restore")
            return False

        # Stage the decryption key on tmpfs, never on disk
        identity_local = self.get_backup_age_identity()
        identity_remote = ""
        if identity_local:
            if not os.path.exists(identity_local):
                logger.log_error(f"backup_age_identity points at a missing file: {identity_local}")
                return False
            with open(identity_local, "r") as identity_file:
                identity_contents = identity_file.read()
            identity_remote = f"/dev/shm/joybox_age_{self.app_name}.key"
            if not self.connection.write_file(identity_remote, identity_contents):
                logger.log_error("Could not stage the age identity on the server")
                return False
            self.connection.change_permission(identity_remote, "600")

        # Run restore
        logger.log_warning(f"Restoring {self.app_name} from {self.get_backup_dir()}/{backup_id}")
        try:
            code = self.connection.run_blocking(
                ["bash", "-c", self.build_restore_script(backup_id, identity_remote)])
        finally:
            if identity_remote:
                self.connection.remove_file_or_directory(identity_remote)
        if code != 0:
            logger.log_error(f"Restore of {self.app_name} failed (exit {code})")
            return False
        return True

    def install_nginx_config(self):
        nginx_tmp_path = f"/tmp/{self.app_name}.conf"
        if self.connection.write_file(nginx_tmp_path, self.nginx_config_template.format(**self.nginx_config_values)):
            self.connection.run_checked([self.nginx_manager_tool, self.get_nginx_action("install"), nginx_tmp_path], sudo = True)
            self.connection.run_checked([self.nginx_manager_tool, self.get_nginx_action("link"), f"{self.app_name}.conf"], sudo = True)
            self.connection.remove_file_or_directory(nginx_tmp_path)
        return True

    def uninstall_nginx_config(self):
        self.connection.run_checked([self.nginx_manager_tool, self.get_nginx_action("remove"), f"{self.app_name}.conf"], sudo = True)
        return True

    def install(self):

        # Check required settings
        logger.log_info("Checking settings")
        if not self.check_required_settings():
            return False

        # Create directories
        logger.log_info("Creating directories")
        app_dir = self.get_app_dir()
        self.connection.make_directory(app_dir)
        self.connection.change_permission(app_dir, "700")
        for subdir in self.app_subdirs:
            self.connection.make_directory(f"{app_dir}/{subdir}")

        # Write docker compose
        logger.log_info("Writing docker compose")
        compose_tmp_path = f"/tmp/{self.app_name}.docker-compose.yml"
        if not self.connection.write_file(compose_tmp_path, self.docker_compose_template):
            logger.log_error(f"Unable to write docker compose for {self.app_name}")
            return False
        self.connection.move_file_or_directory(compose_tmp_path, f"{app_dir}/docker-compose.yml")

        # Write docker env
        logger.log_info("Writing docker env")
        env_tmp_path = f"/tmp/{self.app_name}.env"
        env_contents = self.env_template.format(**self.env_values) + self.get_image_env_lines()
        if not self.connection.write_file(env_tmp_path, env_contents):
            logger.log_error(f"Unable to write docker env for {self.app_name}")
            return False

        # The env file holds database and admin passwords, so lock it down
        # while it is still staged in a world-readable /tmp.
        self.connection.change_permission(env_tmp_path, "600")
        self.connection.move_file_or_directory(env_tmp_path, f"{app_dir}/.env")
        self.connection.change_permission(f"{app_dir}/.env", "600")

        # Create Nginx entry
        logger.log_info("Creating Nginx entry")
        self.install_nginx_config()

        # Open firewall ports
        if self.nginx_ports:
            logger.log_info("Opening firewall ports")
            for port in self.nginx_ports:
                self.connection.run_checked([self.nginx_manager_tool, "open_port", port], sudo = True)

        # Restart Nginx
        logger.log_info("Restarting Nginx")
        self.connection.run_checked([self.nginx_manager_tool, "systemctl", "restart"], sudo = True)

        # Start docker
        logger.log_info("Starting docker")
        self.connection.set_current_working_directory(app_dir)
        self.connection.run_checked(self.docker_compose_command + ["--env-file", f"{app_dir}/.env", "up", "-d", "--build"])
        self.connection.set_current_working_directory(None)

        # Post install
        return self.post_install()

    def post_install(self):
        return True

    def wait_for_service_health(self, service, timeout_seconds = 300):

        # Compose only guarantees the container started; an app behind it may
        # still be initialising.
        logger.log_info(f"Waiting for {service} to become healthy")
        lookup = self.get_container_lookup(service)
        script = """set -eu
for i in $(seq 1 %d); do
    CID="$(%s)"
    if [ -n "$CID" ]; then
        STATUS="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$CID" 2>/dev/null || echo starting)"
        if [ "$STATUS" = "healthy" ] || [ "$STATUS" = "running" ]; then
            echo "%s is $STATUS"
            exit 0
        fi
    fi
    sleep 1
done
echo "Timed out waiting for %s"
exit 1
""" % (timeout_seconds, lookup, service, service)
        return self.connection.run_return_code(["sh", "-c", script]) == 0

    def uninstall(self):

        # Stop docker
        logger.log_info("Stopping docker")
        self.compose_down()

        # Retire directory
        logger.log_info("Retiring directory")
        self.retire_app_dir()

        # Remove Nginx entry
        logger.log_info("Removing Nginx entry")
        self.uninstall_nginx_config()

        # Close firewall ports
        if self.nginx_ports:
            logger.log_info("Closing firewall ports")
            for port in self.nginx_ports:
                self.connection.run_checked([self.nginx_manager_tool, "close_port", port], sudo = True)

        # Restart Nginx
        logger.log_info("Restarting Nginx")
        self.connection.run_checked([self.nginx_manager_tool, "systemctl", "restart"], sudo = True)
        return True
