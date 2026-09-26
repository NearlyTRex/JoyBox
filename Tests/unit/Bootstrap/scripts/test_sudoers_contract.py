# Imports
import os
import re
import subprocess

# Local imports
from joybox import hardening
from fakes import RecordingConnection


###########################################################
# Sudoers grants against the verification checks
#
# Once sshd hardening closes root login, verify_server runs as the deploy
# user, whose only sudo is what setup_sudoers grants. A check that needs a
# command outside the grant fails on a hardened server and nowhere else.
###########################################################

def read_verify_grants(bootstrap_dir):
    with open(os.path.join(bootstrap_dir, "scripts", "common.sh"), "r") as script:
        contents = script.read()
    block = contents.split('Cmnd_Alias JOYBOX_VERIFY = ', 1)[1].split('echo ""', 1)[0]
    entries = re.findall(r'echo "\s*(/[^",\\]+?)(?:,)?\s*(?:\\\\)?"', block)
    return {" ".join([os.path.basename(entry.split()[0])] + entry.split()[1:]) for entry in entries}


def privileged_check_commands():
    connection = RecordingConnection()
    hardening.verify_hardening(connection, domain = "joybox.test")
    return {
        " ".join(call[1][0])
        for call in connection.calls
        if call[0].startswith("run_") and call[2].get("sudo")
    }


def test_every_privileged_check_is_granted(bootstrap_dir):
    granted = read_verify_grants(bootstrap_dir)
    needed = privileged_check_commands()

    assert needed, "the checks no longer run anything with sudo; update this test"
    assert needed <= granted, "not granted: %s" % sorted(needed - granted)


def test_the_verify_grant_is_given_to_the_user(bootstrap_dir):
    with open(os.path.join(bootstrap_dir, "scripts", "common.sh"), "r") as script:
        contents = script.read()

    assert "NOPASSWD: APT_MANAGE, JOYBOX_VERIFY," in contents


###########################################################
# Sudoers grants against the aptget component
#
# Remote sudo is `sudo -n <argv>`, so each argv must match a granted command
# exactly, arguments included.
###########################################################

def render_sudoers(bootstrap_dir, tmp_path):
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    visudo = stub_dir / "visudo"
    visudo.write_text("#!/bin/sh\nexit 0\n")
    visudo.chmod(0o755)
    sudoers_file = tmp_path / "sudoers"
    scripts_dir = os.path.join(bootstrap_dir, "scripts")
    subprocess.run([
        "bash", "-c",
        'source "$1/common.sh" && load_packages "$1/serverpackages.txt" '
        '&& load_managers "$1/servermanagers.txt" && setup_sudoers deploy "$2"',
        "render", scripts_dir, str(sudoers_file)],
        check = True, capture_output = True,
        env = dict(os.environ, PATH = "%s:%s" % (stub_dir, os.environ["PATH"])))
    return sudoers_file.read_text()


def read_granted_commands(sudoers):
    commands = set()
    for line in sudoers.splitlines():
        entry = line.strip().rstrip("\\").strip().rstrip(",")
        if entry.startswith("/"):
            commands.add(re.sub(r"\\(.)", r"\1", entry))
    return commands


# sudo resolves a bare name through the server's secure_path, where Ubuntu
# keeps these in /usr/bin
def resolve_on_server(program):
    return program if program.startswith("/") else "/usr/bin/" + program


def test_every_remote_apt_install_is_granted(bootstrap_dir, tmp_path, isolated_settings):
    from joybox.bootstrap.environments import env_remote_ubuntu
    granted = read_granted_commands(render_sudoers(bootstrap_dir, tmp_path))
    environment = env_remote_ubuntu.RemoteUbuntu(ssh_host = "server.test")
    installer = environment.available_components["aptget"]
    connection = RecordingConnection(command_output = {"policy": "Candidate: 1.0"})
    installer.connection = connection

    assert installer.install()
    needed = {
        " ".join([resolve_on_server(call[1][0][0])] + list(call[1][0][1:]))
        for call in connection.calls
        if call[0].startswith("run_") and call[2].get("sudo")
    }
    assert needed, "aptget no longer runs anything with sudo; update this test"
    assert needed <= granted, "not granted: %s" % sorted(needed - granted)
