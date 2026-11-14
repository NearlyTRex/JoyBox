# Third-party imports
import pytest

# Local imports
from joybox import runoptions
from fakes import RecordingConnection

# Home the recording connection reports for the deploy user
DOCKER_APP_HOME = "/home/deploy"


# A Docker app installer on a recording connection, with its rendered files
class DockerApp:
    def __init__(self, installer_class, pretend_run = False, **world):
        command_output = {"printf": DOCKER_APP_HOME}
        command_output.update(world.pop("command_output", {}))
        self.connection = RecordingConnection(command_output = command_output, **world)
        self.installer = installer_class(
            self.connection, runoptions.RunFlags(verbose = False, pretend_run = pretend_run))
        self.app_dir = f"{DOCKER_APP_HOME}/apps/{self.installer.app_name}"

    # The .env file as install would write it
    def env(self):
        return self.installer.env_template.format(**self.installer.env_values) + self.installer.get_image_env_lines()

    # The nginx config as install would write it
    def nginx(self):
        return self.installer.nginx_config_template.format(**self.installer.nginx_config_values)


# Build a DockerApp against scratch settings
@pytest.fixture
def docker_app(isolated_settings):
    return DockerApp
