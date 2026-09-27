# Local imports
import joybox.bootstrap.installers as installers
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
