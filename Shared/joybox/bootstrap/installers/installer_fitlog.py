# Local imports
from joybox import settings
from joybox import serverinfo
from . import installer_dockerapp
from joybox import runoptions
from joybox import logger

# Docker compose template
#
# Compose builds straight from the git tag, so FitLog's own Dockerfile is the
# one that runs. Named volumes rather than bind mounts: with userns-remap the
# container cannot write host directories, while a new volume takes the
# ownership the image gives its mount point. On first start the app clones the
# catalog into its volume, then pulls it on a timer.
docker_compose_template = """
services:
  fitlog:
    build:
      context: ${FITLOG_REPOSITORY}#${FITLOG_VERSION}
    image: fitlog:${FITLOG_VERSION}
    container_name: fitlog
    restart: always
    ports:
      - "127.0.0.1:${FITLOG_PORT_HTTP}:8000"
    volumes:
      - fitlog_state:/data
      - fitlog_catalog:/catalog
    environment:
      FITLOG_CATALOG_URL: ${FITLOG_REPOSITORY}
      FITLOG_CATALOG_BRANCH: ${FITLOG_CATALOG_BRANCH}
      FITLOG_TIMEZONE: ${FITLOG_TIMEZONE}
      FITLOG_PULL_MINUTES: ${FITLOG_PULL_MINUTES}

      # nginx sets X-Real-IP, which the login rate limit keys on.
      FITLOG_TRUST_PROXY: "1"

volumes:
  fitlog_state:
  fitlog_catalog:
"""

# Env template
env_template = """
FITLOG_REPOSITORY={repository}
FITLOG_CATALOG_BRANCH={catalog_branch}
FITLOG_PORT_HTTP={port_http}
FITLOG_TIMEZONE={timezone}
FITLOG_PULL_MINUTES={pull_minutes}
"""

# FitLog Installer
class FitLog(installer_dockerapp.DockerAppInstaller):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.app_name = "fitlog"
        self.nginx_config_values = {
            "domain": serverinfo.get_domain_name(),
            "subdomain": settings.get_value("UserData.FitLog", "fitlog_subdomain"),
            "port_http": settings.get_value("UserData.FitLog", "fitlog_port_http")
        }
        self.env_values = {
            "repository": "https://github.com/NearlyTRex/FitLog.git",
            "catalog_branch": settings.get_value("UserData.FitLog", "fitlog_catalog_branch",
                default_value = "main", throw_exception = False),
            "port_http": settings.get_value("UserData.FitLog", "fitlog_port_http"),
            "timezone": settings.get_value("UserData.FitLog", "fitlog_timezone",
                default_value = "Etc/UTC", throw_exception = False),
            "pull_minutes": settings.get_value("UserData.FitLog", "fitlog_pull_minutes",
                default_value = "10", throw_exception = False)
        }

        # Templates
        self.docker_compose_template = docker_compose_template
        self.env_template = env_template

        # Behavior
        self.required_settings = ["domain", "subdomain", "port_http", "timezone"]

        # Login
        self.login_user = settings.get_value("UserData.FitLog", "fitlog_user",
            default_value = "", throw_exception = False)
        self.login_pass = settings.get_value("UserData.FitLog", "fitlog_pass",
            default_value = "", throw_exception = False)

        # Backup
        # The SQLite database: food log, workout plans, settings and the login.
        # The catalog volume is a clone of the repo, so it is not backed up.
        self.backup_label = "FitLog"
        self.backup_volumes = ["fitlog_state"]

    def post_install(self):

        # Without a login in the ini, it is created by hand
        create_command = f"cd {self.get_app_dir()} && docker compose exec fitlog fitlog user create <name>"
        if not self.login_user or not self.login_pass:
            logger.log_info("FitLog is running. Set fitlog_user and fitlog_pass, or create the login once, on the server:")
            logger.log_info(f"  {create_command}")
            return True
        if self.flags.pretend_run:
            return True
        if not self.wait_for_service_health("fitlog"):
            logger.log_error("FitLog did not start, so the login was not created")
            return False

        # The CLI reads the password and its confirmation from stdin
        logger.log_info(f"Creating the FitLog login for {self.login_user}")
        password_path = f"{self.get_app_dir()}/.login-password"
        if not self.write_secret_file(password_path, f"{self.login_pass}\n{self.login_pass}\n"):
            logger.log_error("Unable to stage the FitLog password")
            return False
        output = self.connection.run_output(["sh", "-c",
            'docker exec -i fitlog fitlog user create "$1" < "$2" 2>&1; echo "exit=$?"',
            "sh", self.login_user, password_path])
        self.connection.remove_file_or_directory(password_path)

        # Only one login exists, and its password is not reset on later deploys
        if "A user already exists" in output:
            logger.log_info("FitLog already has its login; change it with fitlog user reset-password")
            return True
        if "Created user" not in output:
            logger.log_error("Unable to create the FitLog login:")
            logger.log_error(output)
            return False

        # The authenticator secret goes to the console only, never the log files
        logger.log_info("FitLog login created. Enroll it in an authenticator app now; it is shown once:")
        logger.log_output(output[output.index("Created user"):output.rindex("exit=")] + "\n")
        return True
