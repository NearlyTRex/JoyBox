# Imports
import os
import sys
import copy

# Local imports
import joyboxshared
from joybox import runoptions
from joybox import logger
from joybox import runtime
from joybox import settings

# Environment
class Environment:
    def __init__(
        self,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        self.flags = flags.copy()
        self.options = options.copy()
        self.components_to_process = None
        self.available_components = {}

    def set_environment_type(self, environment_type):
        settings.set_value("UserData.General", "environment_type", environment_type)

    def get_environment_type(self):
        return settings.get_value("UserData.General", "environment_type")

    def set_components_to_process(self, components):
        if components is not None:
            available = set(self.get_available_components())
            specified = set(components)
            invalid = specified - available
            if invalid:
                logger.log_error(f"Invalid components specified: {', '.join(sorted(invalid))}.")
                logger.log_error(f"Available components: {', '.join(sorted(available))}")
                runtime.quit_program()
        self.components_to_process = components

    def get_available_components(self):
        return list(self.available_components.keys())

    def should_process_component(self, component_name):
        if self.components_to_process is None:
            return True
        return component_name in self.components_to_process

    def process_components(self, action_method_name, reverse_order = False, force = False):
        component_items = list(self.available_components.items())
        if reverse_order:
            component_items = reversed(component_items)
        processed_count = 0
        skipped_count = 0
        for component_name, installer in component_items:
            if self.should_process_component(component_name):
                should_skip = False
                if not force:
                    is_installed = installer.is_installed()
                    if action_method_name.lower() == "install" and is_installed:
                        logger.log_info(f"Skipping {component_name} - already installed")
                        should_skip = True
                        skipped_count += 1
                    elif action_method_name.lower() == "uninstall" and not is_installed:
                        logger.log_info(f"Skipping {component_name} - not installed")
                        should_skip = True
                        skipped_count += 1
                if not should_skip:
                    logger.log_info(f"Starting {action_method_name.title()} of {component_name}")
                    method = getattr(installer, action_method_name)
                    if not method():
                        return False
                    processed_count += 1
        if processed_count == 0 and skipped_count == 0 and self.components_to_process is not None:
            logger.log_warning("No components were processed. Check component names.")
        elif skipped_count > 0:
            logger.log_info(f"Processed {processed_count} components, skipped {skipped_count} components")
        return True

    def status(self):
        results = []
        for component_name, installer in self.available_components.items():
            if self.should_process_component(component_name):
                is_installed = installer.is_installed()
                package_status = installer.get_package_status()
                results.append({
                    "name": component_name,
                    "installed": is_installed,
                    "package_status": package_status
                })
        return results

    def setup(self):
        return False

    def teardown(self):
        return False

    def backup(self):
        return self.process_components("backup")
