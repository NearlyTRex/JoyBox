# Imports
import pytest

# Local imports
import joybox.bootstrap.packages as packages
def test_no_pin_uses_latest():
    # Never "latest": a later rebuild must not cross a major version.
    offenders = []
    for app, pins in packages.docker_images.items():
        for name, tag in pins.items():
            if tag.endswith(":latest") or tag == "latest":
                offenders.append(f"{app}.{name} = {tag}")
    assert not offenders, f"image pins using latest: {offenders}"


def test_every_pin_is_versioned():
    # An untagged reference resolves to latest at pull time.
    offenders = []
    for app, pins in packages.docker_images.items():
        for name, tag in pins.items():
            if name.endswith("_VERSION"):
                continue
            assert isinstance(tag, str) and tag, f"{app}.{name} is empty"
            if ":" not in tag:
                offenders.append(f"{app}.{name} = {tag}")
    assert not offenders, f"image pins with no version tag: {offenders}"


def test_the_backup_helper_is_pinned():
    # Archiving runs inside this container.
    assert packages.docker_images["_backup"]["BACKUP_HELPER_IMAGE"]
