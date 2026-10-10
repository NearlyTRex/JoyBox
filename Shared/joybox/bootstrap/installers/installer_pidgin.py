# Imports
import os

# Local imports
import joybox.bootstrap.constants as constants
from . import installer
from joybox import runoptions
from joybox import logger

# Pidgin AIM/ICQ plugins
# Pidgin itself comes from apt. Upstream dropped the OSCAR protocol after
# 2.14.2, so its AIM and ICQ plugins are compiled from that release against the
# installed libpurple headers (the 2.x plugin ABI is stable) and placed in the
# per-user plugin directory.
OSCAR_SOURCES = [
    "authorization.c",
    "bstream.c",
    "clientlogin.c",
    "kerberos.c",
    "encoding.c",
    "family_admin.c",
    "family_alert.c",
    "family_auth.c",
    "family_bart.c",
    "family_bos.c",
    "family_buddy.c",
    "family_chat.c",
    "family_chatnav.c",
    "family_icq.c",
    "family_icbm.c",
    "family_locate.c",
    "family_oservice.c",
    "family_popup.c",
    "family_feedbag.c",
    "family_stats.c",
    "family_userlookup.c",
    "flap_connection.c",
    "misc.c",
    "msgcookie.c",
    "odc.c",
    "oft.c",
    "oscar.c",
    "oscar_data.c",
    "peer.c",
    "peer_proxy.c",
    "rxhandlers.c",
    "snac.c",
    "tlv.c",
    "userinfo.c",
    "util.c",
    "visibility.c",
]

OSCAR_PROTOCOLS = ["aim", "icq"]

# Stands in for the config.h that upstream's configure would generate
OSCAR_CONFIG_HEADER = """\
#define PACKAGE "pidgin"
#define VERSION "{version}"
#define DISPLAY_VERSION "{version}"
#define ENABLE_NLS 1
#define HAVE_ENDIAN_H 1
#define HAVE_ICONV 1
#define HAVE_LANGINFO_CODESET 1
#define HAVE_TM_GMTOFF 1
#define SIZEOF_TIME_T 8
"""

class Pidgin(installer.Installer):
    def __init__(
        self,
        connection,
        flags = runoptions.RunFlags(),
        options = runoptions.RunOptions()):
        super().__init__(connection, flags, options)
        self.oscar_version = "2.14.2"
        self.oscar_sha256 = "19654ad276b149646371fbdac21bc7620742f2975f7399fed0ffc1a18fbaf603"
        self.archive_path = f"/tmp/pidgin-{self.oscar_version}.tar.bz2"
        self.build_dir = "/tmp/pidgin_oscar_build"

    def get_supported_environments(self):
        return [
            constants.EnvironmentType.LOCAL_UBUNTU,
        ]

    def get_source_url(self):
        return (
            f"https://downloads.sourceforge.net/project/pidgin/Pidgin/"
            f"{self.oscar_version}/pidgin-{self.oscar_version}.tar.bz2")

    def get_plugin_dir(self):
        return os.path.join(os.path.expanduser("~"), ".purple", "plugins")

    def get_plugin_paths(self):
        return [os.path.join(self.get_plugin_dir(), f"lib{protocol}.so") for protocol in OSCAR_PROTOCOLS]

    def is_installed(self):
        return all(self.connection.does_file_or_directory_exist(path) for path in self.get_plugin_paths())

    def get_package_status(self):
        installed = []
        missing = []
        for protocol, path in zip(OSCAR_PROTOCOLS, self.get_plugin_paths(), strict=True):
            if self.connection.does_file_or_directory_exist(path):
                installed.append(f"pidgin-{protocol}")
            else:
                missing.append(f"pidgin-{protocol}")
        return {"installed": installed, "missing": missing}

    def is_archive_verified(self):
        if self.flags.pretend_run:
            return True
        output = self.connection.run_output(["sha256sum", self.archive_path])
        return output.split(" ")[0] == self.oscar_sha256

    def clean_build(self):
        self.connection.remove_file_or_directory(self.archive_path)
        self.connection.remove_file_or_directory(self.build_dir)

    def build_plugin(self, protocol, source_dir, include_dir, cflags, libs):
        output_path = os.path.join(self.build_dir, f"lib{protocol}.so")
        sources = [os.path.join(source_dir, name) for name in OSCAR_SOURCES + [f"lib{protocol}.c"]]
        code = self.connection.run_blocking(
            ["gcc", "-shared", "-fPIC", "-O2", "-fvisibility=hidden",
             "-DHAVE_CONFIG_H", "-DPURPLE_PLUGINS"] +
            cflags + ["-I", source_dir, "-I", include_dir] +
            sources + ["-o", output_path] + libs)
        if code != 0:
            logger.log_error(f"Failed to build the {protocol} plugin")
            return None
        return output_path

    def install(self):

        # Start install
        logger.log_info(f"Installing Pidgin AIM/ICQ plugins from Pidgin {self.oscar_version}")

        # Libpurple headers come from the aptget component
        if self.connection.run_return_code(["pkg-config", "--exists", "purple"]) != 0:
            logger.log_error("libpurple headers not found; install pidgin and libpurple-dev with the aptget component")
            return False

        # Download and verify the source
        self.clean_build()
        self.connection.download_file(self.get_source_url(), self.archive_path)
        if not self.is_archive_verified():
            logger.log_error("Pidgin source archive failed its checksum")
            self.clean_build()
            return False

        # Extract
        self.connection.make_directory(self.build_dir)
        code = self.connection.run_blocking(
            [self.tar_tool, "-xjf", self.archive_path, "-C", self.build_dir])
        if code != 0:
            logger.log_error("Failed to extract the Pidgin source archive")
            self.clean_build()
            return False

        # Private headers that libpurple-dev does not ship
        source_root = os.path.join(self.build_dir, f"pidgin-{self.oscar_version}")
        source_dir = os.path.join(source_root, "libpurple", "protocols", "oscar")
        include_dir = os.path.join(self.build_dir, "include")
        self.connection.make_directory(include_dir)
        self.connection.copy_file_or_directory(
            os.path.join(source_root, "libpurple", "internal.h"),
            os.path.join(include_dir, "internal.h"))
        self.connection.write_file(
            os.path.join(include_dir, "config.h"),
            OSCAR_CONFIG_HEADER.format(version = self.oscar_version))

        # Build each protocol plugin
        cflags = self.connection.run_output(["pkg-config", "--cflags", "purple"]).split()
        libs = self.connection.run_output(["pkg-config", "--libs", "glib-2.0"]).split()
        built = []
        for protocol in OSCAR_PROTOCOLS:
            output_path = self.build_plugin(protocol, source_dir, include_dir, cflags, libs)
            if not output_path:
                self.clean_build()
                return False
            built.append(output_path)

        # Install into the per-user plugin directory
        self.connection.make_directory(self.get_plugin_dir())
        for output_path, plugin_path in zip(built, self.get_plugin_paths(), strict=True):
            self.connection.move_file_or_directory(output_path, plugin_path)
            self.connection.change_permission(plugin_path, "644")
        self.clean_build()

        # Verify installation
        logger.log_info("Verifying installation")
        if not self.is_installed():
            logger.log_error("Pidgin plugin installation verification failed")
            return False

        # All done
        logger.log_info("Pidgin AIM/ICQ plugins installed successfully")
        return True

    def uninstall(self):

        # Start uninstall
        logger.log_info("Uninstalling Pidgin AIM/ICQ plugins")

        # Remove plugins
        for plugin_path in self.get_plugin_paths():
            if self.connection.does_file_or_directory_exist(plugin_path):
                self.connection.remove_file_or_directory(plugin_path)

        # All done
        logger.log_info("Pidgin AIM/ICQ plugins uninstalled")
        return True
