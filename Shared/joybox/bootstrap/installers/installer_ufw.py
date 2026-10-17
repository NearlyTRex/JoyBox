# Local imports
import joybox.bootstrap.constants as constants
from . import installer
from joybox import runoptions
from joybox import logger
from joybox import settings
from joybox import hardening

# Firewall rules to install
# Each rule has: name, description, ports, protocol, and the setting that turns
# it on, so a machine only opens what it serves. Traffic is only allowed from
# [Tools.Sunshine] sunshine_allowed_subnet.
UFW_RULES = [
    {
        "name": "sunshine-tcp",
        "description": "Sunshine pairing, control and web UI",
        "ports": "47984,47989,47990,48010",
        "protocol": "tcp",
        "enabled_by": ("Tools.Sunshine", "sunshine_streaming_host"),
    },
    {
        "name": "sunshine-udp",
        "description": "Sunshine video, audio and input streams",
        "ports": "47998:48000",
        "protocol": "udp",
        "enabled_by": ("Tools.Sunshine", "sunshine_streaming_host"),
    },
]

# Ufw
class Ufw(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.allowed_subnet = settings.get_value("Tools.Sunshine", "sunshine_allowed_subnet", "", throw_exception = False) or ""

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
        ]

    def get_enabled_rules(self):
        return [rule for rule in UFW_RULES
            if settings.get_bool_value(*rule["enabled_by"], default_value = False, throw_exception = False)]

    def get_rule_args(self, rule):
        return ["allow", "from", self.allowed_subnet, "to", "any",
            "port", rule["ports"], "proto", rule["protocol"]]

    def get_rule_comment(self, rule):
        return "joybox-" + rule["name"]

    def is_installed(self):
        rules = self.get_enabled_rules()
        if not rules:
            return True
        status = self.connection.run_output(["ufw", "status"], sudo = True)
        return all(self.get_rule_comment(rule) in status for rule in rules)

    def install(self):

        # Nothing to open on this machine
        rules = self.get_enabled_rules()
        if not rules:
            logger.log_info("No firewall rules are enabled for this machine")
            return True
        if not self.allowed_subnet:
            logger.log_error("No [Tools.Sunshine] sunshine_allowed_subnet is set to allow traffic from")
            return False
        if not hardening.has_command(self.connection, "ufw"):
            logger.log_info("ufw is not installed, so there is no firewall to open")
            return True

        # Add each rule; ufw skips one it already has
        for rule in rules:
            logger.log_info(f"Allowing {rule['protocol']} {rule['ports']} from {self.allowed_subnet}: {rule['description']}")
            if self.connection.run_blocking(
                ["ufw"] + self.get_rule_args(rule) + ["comment", self.get_rule_comment(rule)], sudo = True) != 0:
                logger.log_error(f"Failed to add firewall rule {rule['name']}")
                return False

        # All done
        logger.log_info("Firewall rules installed (they take effect once ufw is enabled)")
        return True

    def uninstall(self):

        # Start uninstall
        logger.log_info("Removing firewall rules")

        # Delete every rule, enabled or not, so turning a setting off cleans up
        for rule in UFW_RULES:
            self.connection.run_blocking(["ufw", "delete"] + self.get_rule_args(rule), sudo = True)

        # All done
        logger.log_info("Firewall rules removed")
        return True
