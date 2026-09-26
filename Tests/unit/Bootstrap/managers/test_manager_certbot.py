# Imports
import os
import subprocess

# Third-party imports
import pytest


###########################################################
# Certbot manager
#
# The account runs this as root without a password, so its arguments are the
# account's to choose. Every refusal here happens before anything is written,
# which is what makes it safe to run unprivileged.
###########################################################

def run_manager(bootstrap_dir, *arguments):
    script = os.path.join(bootstrap_dir, "managers", "manager_certbot.sh")
    env = dict(os.environ, SUDO_UID = str(os.getuid()))
    return subprocess.run(["bash", script] + list(arguments),
                          capture_output = True, text = True, env = env)


@pytest.mark.parametrize("domain", ["../../etc", "example.com/../../etc", "-rf", "localhost", ".example.com"])
def test_install_refuses_a_name_that_is_not_a_domain(bootstrap_dir, tmp_path, domain):
    result = run_manager(bootstrap_dir, "install_pair", domain, str(tmp_path / "a"), str(tmp_path / "b"))

    assert result.returncode != 0
    assert "is not a domain name" in result.stdout


def test_install_refuses_a_file_the_caller_does_not_own(bootstrap_dir, tmp_path):
    # Otherwise it could copy out a file only root can read.
    key = tmp_path / "privkey.pem"
    key.write_text("KEY")
    result = run_manager(bootstrap_dir, "install_pair", "example.com", "/etc/passwd", str(key))

    assert result.returncode != 0
    assert "not a regular file owned by the caller" in result.stdout


def test_install_refuses_a_link(bootstrap_dir, tmp_path):
    link = tmp_path / "fullchain.pem"
    link.symlink_to("/etc/passwd")
    key = tmp_path / "privkey.pem"
    key.write_text("KEY")
    result = run_manager(bootstrap_dir, "install_pair", "example.com", str(link), str(key))

    assert result.returncode != 0
    assert "not a regular file owned by the caller" in result.stdout


def test_install_refuses_something_that_is_not_a_certificate(bootstrap_dir, tmp_path):
    cert = tmp_path / "fullchain.pem"
    cert.write_text("not a certificate")
    key = tmp_path / "privkey.pem"
    key.write_text("not a key")
    result = run_manager(bootstrap_dir, "install_pair", "example.com", str(cert), str(key))

    assert result.returncode != 0
    assert "is not a certificate" in result.stdout


def test_selfsign_refuses_a_bad_name_anywhere_in_the_list(bootstrap_dir):
    result = run_manager(bootstrap_dir, "selfsign", "example.com", "www.example.com", "../../etc")

    assert result.returncode != 0
    assert "is not a domain name" in result.stdout


def test_selfsign_locks_down_the_private_key(bootstrap_dir):
    with open(os.path.join(bootstrap_dir, "managers", "manager_certbot.sh")) as script:
        body = script.read().split("selfsign_cert() {", 1)[1].split("\n}\n", 1)[0]

    assert 'chmod 600 "$CERT_DIR/privkey.pem"' in body
    assert 'chmod 644 "$CERT_DIR/fullchain.pem"' in body
