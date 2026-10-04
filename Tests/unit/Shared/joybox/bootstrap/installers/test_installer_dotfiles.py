# Imports
import os

# Local imports
import joybox.bootstrap.installers as installers
import joybox.bootstrap.constants as constants
from joybox.bootstrap.installers import installer_dotfiles
from fakes import RecordingConnection


###########################################################
# The .bashrc
#
# The managed block goes into the user's .bashrc. Where there is none, it
# starts from the distribution's default, as useradd -m would have made it,
# which is also what enables programmable completion.
###########################################################

def build(existing):
    connection = RecordingConnection()
    dotfiles = installers.Dotfiles(connection)
    connection.existing_paths.update(
        dotfiles.skel_bashrc_path if path == "skel" else getattr(dotfiles, path)
        for path in existing)
    return dotfiles, connection


def test_a_missing_bashrc_starts_from_the_skeleton(isolated_settings):
    dotfiles, connection = build(["skel"])
    assert dotfiles.install()

    assert (dotfiles.skel_bashrc_path, dotfiles.bashrc_path) in connection.copied


def test_an_existing_bashrc_is_kept(isolated_settings):
    dotfiles, connection = build(["skel", "bashrc_path"])
    assert dotfiles.install()

    assert (dotfiles.skel_bashrc_path, dotfiles.bashrc_path) not in connection.copied


###########################################################
# Managed block
###########################################################

class FailingWriteConnection(RecordingConnection):
    def __init__(self, failing_fragment):
        super().__init__()
        self.failing_fragment = failing_fragment

    def write_file(self, src, contents, sudo = False):
        super().write_file(src, contents, sudo = sudo)
        return self.failing_fragment not in src


def test_supported_environments_are_ubuntu(isolated_settings):
    dotfiles, _ = build([])
    assert dotfiles.get_supported_environments() == [
        constants.EnvironmentType.LOCAL_UBUNTU, constants.EnvironmentType.REMOTE_UBUNTU]


def test_is_installed_needs_the_block_in_bashrc(isolated_settings):
    dotfiles, connection = build([])
    assert not dotfiles.is_installed()

    connection.existing_paths.add(dotfiles.bashrc_path)
    connection.file_contents[dotfiles.bashrc_path] = "alias ll='ls -l'\n"
    assert not dotfiles.is_installed()

    connection.file_contents[dotfiles.bashrc_path] = None
    assert not dotfiles.is_installed()

    assert dotfiles.install()
    assert dotfiles.is_installed()


def test_install_writes_shell_files_and_both_blocks(isolated_settings):
    dotfiles, connection = build([])
    assert dotfiles.install()

    for _, dest_name in dotfiles.joybox_shell_files:
        assert connection.written(f".joybox/{dest_name}")
    bashrc = connection.written_files[dotfiles.bashrc_path]
    assert bashrc.startswith(installer_dotfiles.BLOCK_BEGIN)
    assert installer_dotfiles.BLOCK_NOTE in bashrc
    assert f'export JOYBOX_ROOT="{dotfiles.joybox_root}"' in bashrc
    assert 'source "$HOME/.bashrc"' in connection.written_files[dotfiles.bash_profile_path]


def test_existing_content_is_backed_up_once_and_kept(isolated_settings):
    dotfiles, connection = build(["bashrc_path"])
    connection.file_contents[dotfiles.bashrc_path] = "alias ll='ls -l'\n"
    assert dotfiles.install()

    backup = dotfiles.bashrc_path + ".joybox.backup"
    assert (dotfiles.bashrc_path, backup) in connection.copied
    bashrc = connection.written_files[dotfiles.bashrc_path]
    assert bashrc.startswith("alias ll='ls -l'\n\n" + installer_dotfiles.BLOCK_BEGIN)

    # A second run replaces the block in place and leaves the backup alone
    connection.copied.clear()
    assert dotfiles.install()
    assert connection.written_files[dotfiles.bashrc_path] == bashrc
    assert (dotfiles.bashrc_path, backup) not in connection.copied


def test_existing_backup_is_not_overwritten(isolated_settings):
    dotfiles, connection = build(["bashrc_path"])
    backup = dotfiles.bashrc_path + ".joybox.backup"
    connection.existing_paths.add(backup)
    connection.file_contents[dotfiles.bashrc_path] = "alias ll='ls -l'\n"
    assert dotfiles.install()

    assert (dotfiles.bashrc_path, backup) not in connection.copied


def test_block_without_note(isolated_settings):
    dotfiles, connection = build([])
    assert dotfiles.inject_managed_block("/f", "body\n", "B", "E")
    assert connection.written_files["/f"] == "B\nbody\nE\n"


def test_strip_managed_block():
    dotfiles = installers.Dotfiles(RecordingConnection())
    assert dotfiles.strip_managed_block("a\nB\nx\nE\nb\n", "B", "E") == "a\nb\n"
    assert dotfiles.strip_managed_block("a\nB\nx\n", "B", "E") == "a\nB\nx\n"


def test_missing_template_fails_install(isolated_settings, tmp_path):
    dotfiles, connection = build([])
    dotfiles.template_dir = str(tmp_path)
    assert dotfiles.get_template("shell.sh") is None
    assert not dotfiles.install()

    assert dotfiles.bashrc_path not in connection.written_files


def test_skeleton_copy_failure_fails_install(isolated_settings):
    dotfiles, connection = build(["skel"])
    connection.copy_file_or_directory = lambda src, dest, sudo = False: False
    assert not dotfiles.install()


def make_failing(fragment):
    connection = FailingWriteConnection(fragment)
    return installers.Dotfiles(connection), connection


def test_shell_file_write_failure_fails_install(isolated_settings):
    dotfiles, _ = make_failing("shell.sh")
    assert not dotfiles.install()


def test_bashrc_write_failure_fails_install(isolated_settings):
    dotfiles, connection = make_failing(".bashrc")
    assert not dotfiles.install()

    assert dotfiles.bash_profile_path not in connection.written_files


def test_bash_profile_write_failure_fails_install(isolated_settings):
    dotfiles, _ = make_failing(".bash_profile")
    assert not dotfiles.install()


###########################################################
# Captured dotfiles
###########################################################

def home(name):
    return os.path.expandvars(f"$HOME/{name}")


def test_captured_dotfiles_are_deployed_with_backup(isolated_settings, tmp_path):
    dotfiles, connection = build([])
    dotfiles.captured_dir = str(tmp_path)
    (tmp_path / "gitconfig").write_text("[user]\n")
    (tmp_path / "vimrc").write_text("set nu\n")
    (tmp_path / "inputrc").write_text("set bell-style none\n")
    connection.existing_paths.update([home(".gitconfig"), home(".vimrc"), home(".vimrc") + ".joybox.backup"])
    assert dotfiles.install()

    assert (home(".gitconfig"), home(".gitconfig") + ".joybox.backup") in connection.copied
    assert (str(tmp_path / "gitconfig"), home(".gitconfig")) in connection.copied
    assert (home(".vimrc"), home(".vimrc") + ".joybox.backup") not in connection.copied
    assert (str(tmp_path / "vimrc"), home(".vimrc")) in connection.copied
    assert (str(tmp_path / "inputrc"), home(".inputrc")) in connection.copied
    assert (home(".inputrc"), home(".inputrc") + ".joybox.backup") not in connection.copied
    assert not any(dest == home(".tmux.conf") for _, dest in connection.copied)


def test_repo_name_drops_the_leading_dot():
    dotfiles = installers.Dotfiles(RecordingConnection())
    assert dotfiles.get_repo_name(".vimrc") == "vimrc"
    assert dotfiles.get_repo_name("vimrc") == "vimrc"


def test_backup_captures_existing_dotfiles(isolated_settings, tmp_path):
    dotfiles, connection = build([])
    dotfiles.captured_dir = str(tmp_path / "captured")
    connection.existing_paths.add(home(".tmux.conf"))
    assert dotfiles.backup()

    assert dotfiles.captured_dir in connection.made_directories
    assert connection.copied == [(home(".tmux.conf"), os.path.join(dotfiles.captured_dir, "tmux.conf"))]


###########################################################
# Uninstall
###########################################################

def test_uninstall_strips_blocks_restores_backups_and_removes_config(isolated_settings):
    dotfiles, connection = build(["bashrc_path"])
    connection.file_contents[dotfiles.bashrc_path] = "alias ll='ls -l'\n"
    assert dotfiles.install()
    connection.existing_paths.add(home(".inputrc") + ".joybox.backup")
    assert dotfiles.uninstall()

    assert connection.written_files[dotfiles.bashrc_path] == "alias ll='ls -l'\n"
    assert installer_dotfiles.BLOCK_BEGIN not in connection.written_files[dotfiles.bash_profile_path]
    assert (home(".inputrc") + ".joybox.backup", home(".inputrc")) in connection.moved
    assert dotfiles.joybox_config_dir in connection.removed_paths


def test_uninstall_skips_absent_unreadable_and_unmanaged_files(isolated_settings):
    dotfiles, connection = build(["bashrc_path", "bash_profile_path"])
    connection.file_contents[dotfiles.bashrc_path] = None
    connection.file_contents[dotfiles.bash_profile_path] = "export A=1\n"
    assert dotfiles.uninstall()

    assert not connection.written_files
    assert not connection.moved

    dotfiles, connection = build([])
    assert dotfiles.uninstall()
    assert not connection.written_files


def test_uninstall_reports_a_failed_block_removal(isolated_settings):
    dotfiles, connection = make_failing(".bashrc")
    connection.existing_paths.add(dotfiles.bashrc_path)
    connection.file_contents[dotfiles.bashrc_path] = "\n".join(
        [installer_dotfiles.BLOCK_BEGIN, "x", installer_dotfiles.BLOCK_END])
    assert not dotfiles.uninstall()
