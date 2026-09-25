# Imports
import os
import re

# Third-party imports
import pytest

# Local imports
import installers


###########################################################
# Compose templates
#
# Docker inserts DNAT rules ahead of ufw's chains, so a port published on
# 0.0.0.0 is reachable without nginx - and so without TLS, .htpasswd,
# ModSecurity or rate limiting.
###########################################################

PUBLISHED_PORT_RE = re.compile(r'^\s*-\s*"(?P<spec>[^"]+)"\s*$')


def compose_port_specs(compose_template):
    # Port entries inside a compose "ports:" block, as raw "host:container" specs
    specs = []
    in_ports_block = False
    for line in compose_template.split("\n"):
        stripped = line.strip()
        if stripped.startswith("ports:"):
            in_ports_block = True
            continue
        if in_ports_block:
            match = PUBLISHED_PORT_RE.match(line)
            if match:
                specs.append(match.group("spec"))
                continue
            if stripped and not stripped.startswith("#"):
                in_ports_block = False
    return specs


def installer_classes():
    # Every installer class that carries a compose template
    found = []
    for name in dir(installers):
        candidate = getattr(installers, name)
        if not isinstance(candidate, type):
            continue
        template = getattr(candidate, "docker_compose_template", None)
        if isinstance(template, str) and "ports:" in template:
            found.append((name, candidate))
    return found


@pytest.mark.parametrize("app_name", [
    "audiobookshelf",
    "filebrowser",
    "fitlog",
    "jenkins",
    "kanboard",
    "navidrome",
    "oscar",
    "wordpress",
])
def test_published_ports_bind_loopback(app_name, bootstrap_dir):
    # Read the module text rather than instantiating: construction needs a
    # populated config, and the binding is a property of the template itself.
    path = os.path.join(bootstrap_dir, "installers", f"installer_{app_name}.py")
    with open(path, "r") as installer_file:
        source = installer_file.read()

    specs = compose_port_specs(source)
    assert specs, f"{app_name} declares no published ports - did the template change?"

    offenders = [spec for spec in specs if not spec.startswith("127.0.0.1:")]
    assert not offenders, (
        f"{app_name} publishes on all interfaces: {offenders}. "
        "Docker's published ports bypass ufw, so this is reachable without nginx."
    )


def test_every_compose_template_is_covered_by_the_port_test(bootstrap_dir):
    # A new Docker app must be added to the list above, not silently skipped.
    covered = {
        "audiobookshelf", "filebrowser", "fitlog", "jenkins",
        "kanboard", "navidrome", "oscar", "wordpress",
    }
    installers_dir = os.path.join(bootstrap_dir, "installers")
    with_ports = set()
    for filename in os.listdir(installers_dir):
        if not (filename.startswith("installer_") and filename.endswith(".py")):
            continue
        with open(os.path.join(installers_dir, filename), "r") as installer_file:
            source = installer_file.read()
        if "docker_compose_template" in source and compose_port_specs(source):
            with_ports.add(filename[len("installer_"):-3])

    uncovered = sorted(with_ports - covered)
    assert not uncovered, f"compose templates with published ports and no test: {uncovered}"


###########################################################
# Nginx templates
###########################################################

def nginx_template_sources(bootstrap_dir):
    installers_dir = os.path.join(bootstrap_dir, "installers")
    for filename in sorted(os.listdir(installers_dir)):
        if filename.startswith("installer_") and filename.endswith(".py"):
            with open(os.path.join(installers_dir, filename), "r") as installer_file:
                yield filename, installer_file.read()


def test_tls_vhosts_include_shared_params(bootstrap_dir):
    # ssl-params.conf carries the TLS policy, HSTS, security headers and
    # limit_req. A 443 block that skips it opts out of all of them.
    offenders = []
    for filename, source in nginx_template_sources(bootstrap_dir):
        if "listen 443" in source and "ssl-params.conf" not in source:
            offenders.append(filename)
    assert not offenders, f"443 blocks without ssl-params.conf: {offenders}"


def test_tls_vhosts_reference_the_apex_cert_path(bootstrap_dir):
    # Every mode of the certbot installer writes to
    # /etc/letsencrypt/live/<apex>/, so templates must interpolate the apex
    # domain, never the subdomain.
    offenders = []
    for filename, source in nginx_template_sources(bootstrap_dir):
        for match in re.finditer(r"ssl_certificate(?:_key)?\s+(\S+);", source):
            path = match.group(1)
            if "letsencrypt/live/" in path and "{subdomain}" in path:
                offenders.append(f"{filename}: {path}")
    assert not offenders, f"cert paths built from a subdomain: {offenders}"
