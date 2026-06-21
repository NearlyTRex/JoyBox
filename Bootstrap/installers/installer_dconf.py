# Imports
import os
import sys

# Local imports
import constants
from . import installer
from joybox import runoptions
from joybox import logger

# dconf/gsettings settings to apply (desktop only)
# Each setting has: schema, key, value (GVariant text), description
DCONF_SETTINGS = [
    {
        "schema": "org.cinnamon.desktop.peripherals.touchpad",
        "key": "click-method",
        "value": "'areas'",
        "description": "Use button-areas click method (reliable click-drag on the Magic Trackpad)",
    },
]

# Dconf
class Dconf(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
        ]

    def get_available_schemas(self):
        return self.connection.run_output(["gsettings", "list-schemas"]) or ""

    def is_schema_present(self, schemas_text, schema):
        return schema in (schemas_text or "").split()

    def is_installed(self):
        schemas = self.get_available_schemas()
        if not schemas:
            return False
        for setting in DCONF_SETTINGS:
            if not self.is_schema_present(schemas, setting["schema"]):
                continue
            current = self.connection.run_output(
                ["gsettings", "get", setting["schema"], setting["key"]])
            if current is None or current.strip() != setting["value"]:
                return False
        return True

    def install(self):

        # Start install
        logger.log_info("Applying dconf settings")

        # Need gsettings / a desktop session
        schemas = self.get_available_schemas()
        if not schemas:
            if self.flags.pretend_run:
                logger.log_info("Pretend run: would apply dconf settings via gsettings")
                return True
            logger.log_error("gsettings is not available, cannot apply dconf settings")
            return False

        # Apply each setting
        for setting in DCONF_SETTINGS:
            if not self.is_schema_present(schemas, setting["schema"]):
                logger.log_info(f"Schema {setting['schema']} not present, skipping {setting['key']}")
                continue
            logger.log_info(
                f"Setting {setting['schema']} {setting['key']} = {setting['value']}: {setting['description']}")
            code = self.connection.run_blocking(
                ["gsettings", "set", setting["schema"], setting["key"], setting["value"]])
            if code != 0:
                logger.log_error(f"Failed to set {setting['schema']} {setting['key']}")
                return False

        # All done
        logger.log_info("Dconf settings applied successfully")
        return True

    def uninstall(self):

        # Start uninstall
        logger.log_info("Resetting dconf settings")

        # Reset each setting back to its default
        schemas = self.get_available_schemas()
        for setting in DCONF_SETTINGS:
            if not self.is_schema_present(schemas, setting["schema"]):
                continue
            logger.log_info(f"Resetting {setting['schema']} {setting['key']}")
            self.connection.run_blocking(
                ["gsettings", "reset", setting["schema"], setting["key"]])

        # All done
        logger.log_info("Dconf settings reset")
        return True
