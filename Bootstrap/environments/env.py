# Imports
import os
import sys
import copy

# Local imports
import util

# Environment
class Environment:
    def __init__(
        self,
        config,
        flags = util.RunFlags(),
        options = util.RunOptions()):
        self.config = config.Copy()
        self.flags = flags.Copy()
        self.options = options.Copy()
        self.components_to_process = None
        self.available_components = {}

    def SetEnvironmentType(self, environment_type):
        self.config.SetValue("UserData.General", "environment_type", environment_type)

    def GetEnvironmentType(self):
        return self.config.GetValue("UserData.General", "environment_type")

    def SetComponentsToProcess(self, components):
        if components is not None:
            available = set(self.GetAvailableComponents())
            specified = set(components)
            invalid = specified - available
            if invalid:
                util.LogError(f"Invalid components specified: {', '.join(sorted(invalid))}.")
                util.LogError(f"Available components: {', '.join(sorted(available))}")
                util.QuitProgram()
        self.components_to_process = components

    def GetAvailableComponents(self):
        return list(self.available_components.keys())

    def ShouldProcessComponent(self, component_name):
        if self.components_to_process is None:
            return True
        return component_name in self.components_to_process

    def ProcessComponents(self, action_method_name, reverse_order = False):
        component_items = list(self.available_components.items())
        if reverse_order:
            component_items = reversed(component_items)
        processed_count = 0
        for component_name, installer in component_items:
            if self.ShouldProcessComponent(component_name):
                util.LogInfo(f"{action_method_name.title()} {component_name}")
                method = getattr(installer, action_method_name)
                if not method():
                    return False
                processed_count += 1
        if processed_count == 0 and self.components_to_process is not None:
            util.LogWarning("No components were processed. Check component names.")
        return True

    def Setup(self):
        return False

    def Teardown(self):
        return False
