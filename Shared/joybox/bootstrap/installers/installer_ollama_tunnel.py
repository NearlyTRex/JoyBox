# Imports
import os

# Local imports
import joybox.bootstrap.constants as constants
from . import installer
from joybox import runoptions
from joybox import logger
from joybox import settings

# Ports on the server: ollama's API and the hardware helper beside it
SERVER_API_PORT = 11434
SERVER_HELPER_PORT = 11435

# Ollama tunnel
#
# The LLM server's API has no authentication, so it listens on the server's
# own localhost and is reached through SSH, which authenticates with the
# account's key. This keeps a tunnel up as a systemd user service: the API
# on [Tools.Ollama] ollama_tunnel_port here (not 11434, which a local ollama
# may hold) and the helper on its own port, which is where ollama_tool looks
# for it. [Tools.Ollama] ollama_api_base should then be the tunnel's end,
# http://localhost:<tunnel port>.
class OllamaTunnel(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.ssh_host = settings.get_value("Tools.Ollama", "ollama_ssh_host", "", throw_exception = False) or ""
        self.tunnel_port = settings.get_value("Tools.Ollama", "ollama_tunnel_port", "11444", throw_exception = False)
        self.unit_name = "ollama-tunnel.service"
        self.unit_path = os.path.join(os.path.expanduser("~"), ".config", "systemd", "user", self.unit_name)

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
        ]

    def is_installed(self):
        return self.connection.does_file_or_directory_exist(self.unit_path)

    def get_package_status(self):
        if self.is_installed():
            return {"installed": ["ollama-tunnel"], "missing": []}
        return {"installed": [], "missing": ["ollama-tunnel"]}

    # The unit that keeps the tunnel up
    # BatchMode makes a missing key fail rather than wait for a password, and
    # ExitOnForwardFailure makes a taken port fail rather than run with no
    # tunnel; either way systemd retries. Both ends bind to localhost only.
    def build_unit(self):
        forwards = [
            "-L", "127.0.0.1:%s:127.0.0.1:%d" % (self.tunnel_port, SERVER_API_PORT),
            "-L", "127.0.0.1:%d:127.0.0.1:%d" % (SERVER_HELPER_PORT, SERVER_HELPER_PORT),
        ]
        command = ["/usr/bin/ssh", "-N",
            "-o", "BatchMode=yes",
            "-o", "ExitOnForwardFailure=yes",
            "-o", "ServerAliveInterval=30",
            "-o", "ServerAliveCountMax=3"] + forwards + [self.ssh_host]
        return (
            "[Unit]\n"
            "Description=SSH tunnel to the Ollama server at %s\n"
            "After=network-online.target\n"
            "\n"
            "[Service]\n"
            "ExecStart=%s\n"
            "Restart=always\n"
            "RestartSec=10\n"
            "\n"
            "[Install]\n"
            "WantedBy=default.target\n" % (self.ssh_host, " ".join(command)))

    def install(self):

        # Nothing to do without a server to reach
        if not self.ssh_host:
            logger.log_info("No [Tools.Ollama] ollama_ssh_host is set, so there is no tunnel to keep up")
            return True

        # Write the unit
        logger.log_info(f"Installing the SSH tunnel to the Ollama server at {self.ssh_host}")
        self.connection.make_directory(os.path.dirname(self.unit_path))
        if not self.connection.write_file(self.unit_path, self.build_unit()):
            logger.log_error(f"Failed to write {self.unit_path}")
            return False

        # Start it, and again at every login
        for cmd in (["systemctl", "--user", "daemon-reload"],
                    ["systemctl", "--user", "enable", "--now", self.unit_name]):
            if self.connection.run_blocking(cmd) != 0:
                logger.log_error(f"Failed to run: {' '.join(cmd)}")
                return False

        # All done
        logger.log_info(f"Tunnel up: point [Tools.Ollama] ollama_api_base at http://localhost:{self.tunnel_port}")
        return True

    def uninstall(self):

        # Start uninstall
        logger.log_info("Removing the SSH tunnel to the Ollama server")

        # Stop it and remove the unit
        if self.connection.does_file_or_directory_exist(self.unit_path):
            self.connection.run_blocking(["systemctl", "--user", "disable", "--now", self.unit_name])
            if not self.connection.remove_file_or_directory(self.unit_path):
                logger.log_error(f"Failed to remove {self.unit_path}")
                return False
            self.connection.run_blocking(["systemctl", "--user", "daemon-reload"])

        # All done
        logger.log_info("Ollama tunnel removed")
        return True
