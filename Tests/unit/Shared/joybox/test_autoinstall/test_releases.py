# Third-party imports
import pytest

# Local imports
from joybox import autoinstall
from autoinstall_helpers import image_named, listing_with


###########################################################
# Choosing a release
#
# The build takes whatever the release page lists as newest. Picking the
# wrong entry installs an older point release, which is a different kernel
# than the one the profile was written against.
###########################################################

def test_a_release_listing_is_addressed_by_version():
    assert autoinstall.get_release_listing_url("24.04") == \
        "https://releases.ubuntu.com/24.04/"


def test_the_published_images_are_found(release_page):
    release_page["html"] = listing_with(image_named("24.04.1"), image_named("24.04.2"))

    assert autoinstall.find_release_images("24.04") == [
        image_named("24.04.1"), image_named("24.04.2")]


def test_an_image_listed_twice_is_returned_once(release_page):
    # The page links each image more than once.
    release_page["html"] = listing_with(image_named("24.04.1"), image_named("24.04.1"))

    assert autoinstall.find_release_images("24.04") == [image_named("24.04.1")]


def test_the_newest_point_release_is_taken(release_page):
    release_page["html"] = listing_with(image_named("24.04.1"), image_named("24.04.3"))

    assert autoinstall.find_latest_release_image("24.04") == image_named("24.04.3")


def test_point_releases_are_ordered_as_numbers(release_page):
    # Sorted as text, 24.04.10 comes before 24.04.2 and the build silently
    # installs an older release.
    release_page["html"] = listing_with(image_named("24.04.2"), image_named("24.04.10"))

    assert autoinstall.find_latest_release_image("24.04") == image_named("24.04.10")


def test_a_release_with_no_point_release_is_ordered_first(release_page):
    release_page["html"] = listing_with(image_named("24.04.1"), image_named("24.04"))

    assert autoinstall.find_latest_release_image("24.04") == image_named("24.04.1")


def test_a_desktop_image_is_not_taken_for_a_server_one(release_page):
    release_page["html"] = listing_with(
        "ubuntu-24.04.1-desktop-amd64.iso", image_named("24.04.1"))

    assert autoinstall.find_release_images("24.04") == [image_named("24.04.1")]


def test_the_download_url_is_under_its_release(release_page):
    release_page["html"] = listing_with(image_named("24.04.1"))

    assert autoinstall.find_latest_release_url("24.04") == \
        "https://releases.ubuntu.com/24.04/" + image_named("24.04.1")


def test_a_page_with_no_images_finds_nothing(release_page):
    release_page["html"] = "<html><body>nothing here</body></html>"

    assert autoinstall.find_release_images("24.04") == []
    assert autoinstall.find_latest_release_image("24.04") is None
    assert autoinstall.find_latest_release_url("24.04") is None


def test_a_page_that_could_not_be_fetched_finds_nothing(release_page):
    release_page["html"] = None

    assert autoinstall.find_release_images("24.04") == []


@pytest.mark.parametrize("image,expected", [
    (image_named("24.04"), (24, 4)),
    (image_named("24.04.1"), (24, 4, 1)),
    ("not-an-image.iso", ()),
])
def test_an_image_version_is_read_as_numbers(image, expected):
    assert autoinstall.get_image_version(image) == expected


def test_an_empty_version_part_is_skipped():
    assert autoinstall.get_image_version("ubuntu-24.04.-live-server-amd64.iso") == (24, 4)


def test_the_volume_names_its_release():
    assert autoinstall.get_volume_name("24.04") == "Ubuntu-Server 24.04"
