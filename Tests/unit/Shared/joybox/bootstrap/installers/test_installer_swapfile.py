# Local imports
import joybox.bootstrap.constants as constants
import joybox.bootstrap.installers as installers
from joybox.bootstrap.installers import installer_swapfile
from joybox import runoptions
from fakes import RecordingConnection


###########################################################
# Swapfile
#
# Installed means /swapfile is exactly the target size and listed in fstab.
# Resizing has to swap the old file off first, and the fstab edit appends to
# the existing table, never replaces it.
###########################################################

FSTAB = "UUID=abcd / ext4 errors=remount-ro 0 1\n"
SIZE = str(installer_swapfile.SWAPFILE_SIZE_GB * 1024 ** 3)


class UnwritableConnection(RecordingConnection):
    def write_file(self, src, contents, sudo = False):
        self._record("write_file", src, contents, sudo = sudo)
        return False


class UnreadableConnection(RecordingConnection):

    # Only what the installer wrote itself reads back, so fstab reads fail
    def read_file(self, src, sudo = False):
        self._record("read_file", src, sudo = sudo)
        return self.written_files.get(src)


def make(connection = None, size = "2147483648", active = True, fstab = FSTAB):
    connection = connection if connection is not None else RecordingConnection()
    connection.command_output["stat -c %s /swapfile"] = size
    connection.command_output["swapon --show=NAME"] = "/dev/zram0\n/swapfile\n" if active else "/dev/zram0\n"
    connection.file_contents["/etc/fstab"] = fstab
    return installers.Swapfile(connection), connection


def test_only_local_ubuntu_is_supported(isolated_settings):
    swapfile, _ = make()
    assert swapfile.get_supported_environments() == [constants.EnvironmentType.LOCAL_UBUNTU]


def test_installed_needs_the_size_and_the_fstab_entry(isolated_settings):
    assert not make()[0].is_installed()
    assert not make(size = SIZE)[0].is_installed()
    assert make(size = SIZE, fstab = FSTAB + "/swapfile none swap sw 0 0\n")[0].is_installed()


def test_a_commented_entry_does_not_count(isolated_settings):
    swapfile, _ = make(size = SIZE, fstab = FSTAB + "#/swapfile none swap sw 0 0\n")
    assert not swapfile.is_installed()


def test_resizing_swaps_off_before_recreating(isolated_settings):
    swapfile, connection = make(fstab = FSTAB + "/swapfile none swap sw 0 0\n")

    assert swapfile.install()
    run = [command for command in connection.command_strings() if "stat" not in command and "--show" not in command]
    assert run == [
        "swapoff /swapfile",
        "truncate -s 0 /swapfile",
        "fallocate -l 16G /swapfile",
        "chmod 600 /swapfile",
        "mkswap /swapfile",
        "swapon /swapfile",
    ]
    assert connection.written("/etc/fstab") is None


def test_an_inactive_file_is_not_swapped_off(isolated_settings):
    swapfile, connection = make(active = False)

    assert swapfile.install()
    assert not connection.ran("swapoff")
    assert connection.ran("mkswap /swapfile")


def test_a_failed_swapoff_leaves_the_file_alone(isolated_settings):
    swapfile, connection = make(RecordingConnection(return_codes = {"swapoff": 1}))

    assert not swapfile.install()
    assert not connection.ran("fallocate")


def test_the_right_size_is_not_recreated(isolated_settings):
    swapfile, connection = make(size = SIZE)

    assert swapfile.install()
    assert not connection.ran_any("swapoff", "fallocate", "mkswap")


def test_the_fstab_entry_is_appended(isolated_settings):
    swapfile, connection = make(size = SIZE, fstab = FSTAB.rstrip("\n"))

    assert swapfile.install()
    assert connection.written("/etc/fstab") == FSTAB + "/swapfile none swap sw 0 0\n"


def test_an_unreadable_fstab_is_never_overwritten(isolated_settings):
    swapfile, connection = make(UnreadableConnection(), size = SIZE)

    assert not swapfile.install()
    assert connection.written("/etc/fstab") is None


def test_an_unwritable_fstab_fails_the_install(isolated_settings):
    swapfile, _ = make(UnwritableConnection(), size = SIZE)
    assert not swapfile.install()


def test_uninstall_keeps_the_swap_file(isolated_settings):
    swapfile, connection = make()

    assert swapfile.uninstall()
    assert connection.commands == []
    assert connection.removed_paths == []


def test_a_failed_step_stops_the_resize(isolated_settings):
    swapfile, connection = make(RecordingConnection(return_codes = {"fallocate": 1}))

    assert not swapfile.install()
    assert not connection.ran("mkswap")


def test_a_pretend_run_appends_without_reading(isolated_settings):
    connection = UnreadableConnection()
    swapfile = installers.Swapfile(connection, flags = runoptions.RunFlags(pretend_run = True, verbose = False))
    connection.command_output["stat -c %s /swapfile"] = SIZE

    assert swapfile.install()
    assert connection.written("/etc/fstab") == "/swapfile none swap sw 0 0\n"
