# Local imports
from joybox.bootstrap import constants
from joybox import connection
from joybox.bootstrap import installers
from joybox import runoptions
from . import env

# Component name and installer class, in install order
_COMPONENT_INSTALLERS = (
    ("config", "Config"),
    ("aptget", "AptGet"),
    ("keys", "Keys"),
    ("sdl3", "Sdl3"),
    ("dconf", "Dconf"),
    ("dotfiles", "Dotfiles"),
    ("githooks", "GitHooks"),
    ("python", "Python"),
    ("wrappers", "Wrappers"),
    ("autostart", "Autostart"),
    ("awscli", "AwsCli"),
    ("flatpak", "Flatpak"),
    ("node", "Node"),
    ("chrome", "Chrome"),
    ("claude", "Claude"),
    ("deno", "Deno"),
    ("brave", "Brave"),
    ("gh", "Gh"),
    ("gitkraken", "GitKraken"),
    ("hermes", "HermesAgent"),
    ("llamacpp", "LlamaCpp"),
    ("llvm", "Llvm"),
    ("ollama", "Ollama"),
    ("ollama_tunnel", "OllamaTunnel"),
    ("onepassword", "OnePassword"),
    ("pidgin", "Pidgin"),
    ("pipewire", "Pipewire"),
    ("rust", "Rust"),
    ("steam", "Steam"),
    ("sysctl", "Sysctl"),
    ("zram", "Zram"),
    ("swapfile", "Swapfile"),
    ("udev", "Udev"),
    ("ufw", "Ufw"),
    ("vale", "Vale"),
    ("virtualbox", "VirtualBox"),
    ("vscodium", "VSCodium"),
    ("wine", "Wine"),
    ("wireplumber", "Wireplumber"),
    ("xorg", "Xorg")
)

# Local Ubuntu
class LocalUbuntu(env.Environment):
    def __init__(
        self,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(flags, options)

        # Set environment type
        self.set_environment_type(constants.EnvironmentType.LOCAL_UBUNTU)

        # Create connection
        self.connection = connection.ConnectionLocal(self.flags, self.options)

        # Create installer options
        self.installer_options = {
            "connection": self.connection,
            "flags": self.flags,
            "options": self.options
        }

        # Create components
        self.available_components = {
            name: getattr(installers, class_name)(**self.installer_options)
            for name, class_name in _COMPONENT_INSTALLERS}

    # Refresh apt lists, install the selected desktop components carrying on past
    # failures unless exit_on_failure is set, then autoremove when asked
    def setup(self):
        self.connect()
        self.refresh_package_lists()

        # Desktop components are independent, so one failure does not skip the rest
        success = self.process_components("install", force=self.flags.force,
            continue_on_failure = not self.flags.exit_on_failure)
        return self.finish_with_autoremove(success)

    # Uninstall the selected components in reverse order, then autoremove when asked
    def teardown(self):

        # Process components in reverse order
        success = self.process_components("uninstall", reverse_order=True, force=self.flags.force,
            continue_on_failure = not self.flags.exit_on_failure)
        return self.finish_with_autoremove(success)
