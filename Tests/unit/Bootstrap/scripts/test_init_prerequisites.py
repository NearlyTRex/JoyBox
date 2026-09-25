# Imports
import os

# Third-party imports
import pytest


###########################################################
# Day-0 scripts on a fresh server
#
# These run before bootstrap.py has installed anything, so each one installs
# the package it configures before configuring it.
###########################################################

def read_script(bootstrap_dir, name):
    with open(os.path.join(bootstrap_dir, "scripts", name), "r") as script:
        return script.read()


def calls(contents):
    return [line.strip() for line in contents.splitlines()
            if line.strip() and not line.strip().startswith("#")]


@pytest.mark.parametrize("script, install, first_use", [
    ("init_docker.sh", "install_docker", 'configure_docker_group "$USERNAME"'),
    ("init_nginx.sh", "install_nginx", "configure_unattended_upgrades"),
])
def test_the_package_is_installed_before_it_is_configured(bootstrap_dir, script, install, first_use):
    lines = calls(read_script(bootstrap_dir, script))

    assert install in lines
    assert lines.index(install) < lines.index(first_use)


@pytest.mark.parametrize("function, package", [
    ("install_docker", "docker.io"),
    ("install_nginx", "nginx"),
])
def test_the_installed_package_is_the_one_bootstrap_manages(bootstrap_dir, function, package):
    common_sh = read_script(bootstrap_dir, "common.sh")
    body = common_sh.split("%s() {" % function, 1)[1].split("\n}\n", 1)[0]
    managed = [line.strip() for line in read_script(bootstrap_dir, "serverpackages.txt").splitlines()]

    assert "apt-get install -y %s" % package in body
    assert package in managed
