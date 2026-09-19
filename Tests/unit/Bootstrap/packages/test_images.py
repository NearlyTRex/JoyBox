# Imports
import pytest

# Local imports
import packages


def test_no_pin_uses_latest():

    # images.py states the policy explicitly: never "latest", because a rebuild
    # months later must not silently cross a major version.
    offenders = []
    for app, pins in packages.docker_images.items():
        for name, tag in pins.items():
            if tag.endswith(":latest") or tag == "latest":
                offenders.append(f"{app}.{name} = {tag}")
    assert not offenders, f"image pins using latest: {offenders}"


def test_every_pin_is_versioned():

    # An image reference with no tag resolves to latest at pull time, which is
    # the same failure wearing a different hat.
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

    # Backup and restore run archiving inside this container, so an unpinned
    # helper would change the tar behaviour under an unrelated rebuild.
    assert packages.docker_images["_backup"]["BACKUP_HELPER_IMAGE"]
