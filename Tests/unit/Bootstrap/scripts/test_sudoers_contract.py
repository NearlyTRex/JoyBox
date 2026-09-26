# Imports
import os
import re

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
