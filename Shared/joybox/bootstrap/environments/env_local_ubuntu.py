# Local imports
from joybox.bootstrap import constants
from joybox import connection
from joybox.bootstrap import installers
from joybox import runoptions
from joybox import logger
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

        # Get individual installers
        self._bind_installers()

    # Expose each component's installer as an installer_<name> attribute
    def _bind_installers(self):
        self.installer_config = self.available_components["config"]
        self.installer_dconf = self.available_components["dconf"]
        self.installer_dotfiles = self.available_components["dotfiles"]
        self.installer_githooks = self.available_components["githooks"]
        self.installer_python = self.available_components["python"]
        self.installer_wrappers = self.available_components["wrappers"]
        self.installer_aptget = self.available_components["aptget"]
        self.installer_keys = self.available_components["keys"]
        self.installer_sdl3 = self.available_components["sdl3"]
        self.installer_autostart = self.available_components["autostart"]
        self.installer_awscli = self.available_components["awscli"]
        self.installer_flatpak = self.available_components["flatpak"]
        self.installer_node = self.available_components["node"]
        self.installer_chrome = self.available_components["chrome"]
        self.installer_claude = self.available_components["claude"]
        self.installer_deno = self.available_components["deno"]
        self.installer_brave = self.available_components["brave"]
        self.installer_gh = self.available_components["gh"]
        self.installer_gitkraken = self.available_components["gitkraken"]
        self.installer_hermes = self.available_components["hermes"]
        self.installer_llvm = self.available_components["llvm"]
        self.installer_ollama = self.available_components["ollama"]
        self.installer_ollama_tunnel = self.available_components["ollama_tunnel"]
        self.installer_onepassword = self.available_components["onepassword"]
        self.installer_pidgin = self.available_components["pidgin"]
        self.installer_pipewire = self.available_components["pipewire"]
        self.installer_rust = self.available_components["rust"]
        self.installer_steam = self.available_components["steam"]
        self.installer_sysctl = self.available_components["sysctl"]
        self.installer_zram = self.available_components["zram"]
        self.installer_swapfile = self.available_components["swapfile"]
        self.installer_udev = self.available_components["udev"]
        self.installer_ufw = self.available_components["ufw"]
        self.installer_virtualbox = self.available_components["virtualbox"]
        self.installer_vscodium = self.available_components["vscodium"]
        self.installer_wine = self.available_components["wine"]
        self.installer_wireplumber = self.available_components["wireplumber"]
        self.installer_xorg = self.available_components["xorg"]

    # Refresh apt lists, install the selected desktop components carrying on past
    # failures unless exit_on_failure is set, then autoremove when asked
    def setup(self):
        self.connect()

        # Update package lists
        if self.should_process_component("aptget"):
            logger.log_info("Updating package lists for AptGet")
            self.installer_aptget.update_package_lists()

        # Desktop components are independent, so one failure does not skip the rest
        success = self.process_components("install", force=self.flags.force,
            continue_on_failure = not self.flags.exit_on_failure)

        # Autoremove packages (opt-in: --autoremove, off by default)
        if self.flags.autoremove and self.should_process_component("aptget") and success:
            logger.log_info("Auto-removing unused packages")
            if not self.installer_aptget.auto_remove_packages():
                return False
        return success

    # Uninstall the selected components in reverse order, then autoremove when asked
    def teardown(self):

        # Process components in reverse order
        success = self.process_components("uninstall", reverse_order=True, force=self.flags.force,
            continue_on_failure = not self.flags.exit_on_failure)

        # Autoremove packages (opt-in: --autoremove, off by default)
        if self.flags.autoremove and self.should_process_component("aptget") and success:
            logger.log_info("Auto-removing unused packages")
            if not self.installer_aptget.auto_remove_packages():
                return False
        return success
