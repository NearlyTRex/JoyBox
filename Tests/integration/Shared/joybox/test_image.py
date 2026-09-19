# Imports
import base64
import pytest

# Local imports
from joybox import config, image

PIL = pytest.importorskip("PIL.Image")


###########################################################
# Image conversion
#
# Box art and embedded album artwork are normalized through these, and every
# failure path returns False rather than raising, so a silent no-op looks like
# a source that simply was not an image.
###########################################################

def make_image(path, colour = "red", size = (8, 8), **options):
    PIL.new("RGB", size, colour).save(str(path), **options)
    return str(path)


def make_animated_gif(path, frames = 3):
    images = [PIL.new("RGB", (8, 8), colour) for colour in ["red", "green", "blue"][:frames]]
    images[0].save(str(path), save_all = True, append_images = images[1:], duration = 50, loop = 0)
    return str(path)


def opened_format(path):
    with PIL.open(str(path)) as handle:
        return handle.format


###########################################################
# Format detection
###########################################################

def test_a_jpeg_file_is_detected(tmp_path):
    source = make_image(tmp_path / "art.jpg")

    assert image.get_image_format(source) == config.ImageFileType.JPEG
    assert image.is_image_jpeg(source) is True
    assert image.is_image_png(source) is False


def test_a_png_file_is_detected(tmp_path):
    source = make_image(tmp_path / "art.png")

    assert image.get_image_format(source) == config.ImageFileType.PNG
    assert image.is_image_png(source) is True
    assert image.is_image_jpeg(source) is False


def test_contents_win_over_the_extension(tmp_path):
    # Scrapers hand back files named .jpg that hold png data.
    source = tmp_path / "art.jpg"
    PIL.new("RGB", (8, 8), "red").save(str(source), format = "PNG")

    assert image.get_image_format(str(source)) == config.ImageFileType.PNG


def test_an_unsupported_format_is_unknown(tmp_path):
    source = make_image(tmp_path / "art.bmp")

    assert image.get_image_format(source) is None


def test_a_non_image_file_is_unknown(tmp_path):
    source = tmp_path / "art.jpg"
    source.write_text("not an image")

    assert image.get_image_format(str(source)) is None


@pytest.mark.parametrize("name,expected", [
    ("art.jpg", config.ImageFileType.JPEG),
    ("art.jpeg", config.ImageFileType.JPEG),
    ("art.JPG", config.ImageFileType.JPEG),
    ("art.png", config.ImageFileType.PNG),
    ("art.PNG", config.ImageFileType.PNG),
    ("art.bmp", None),
    ("art", None),
])
def test_a_missing_file_falls_back_to_its_extension(tmp_path, name, expected):
    # Callers ask about a destination that does not exist yet.
    assert image.get_image_format(str(tmp_path / name)) == expected


###########################################################
# Conversion
###########################################################

def test_a_jpeg_is_converted_to_png(tmp_path):
    # A jpeg carries no animation flag at all, which is not a reason to refuse
    # to convert it.
    source = make_image(tmp_path / "art.jpg")
    target = tmp_path / "art.png"

    assert image.convert_image_to_png(source, str(target)) is True
    assert target.exists()
    assert opened_format(target) == "PNG"


def test_a_png_is_converted_to_jpeg(tmp_path):
    source = make_image(tmp_path / "art.png")
    target = tmp_path / "art.jpg"

    assert image.convert_image_to_jpeg(source, str(target)) is True
    assert opened_format(target) == "JPEG"


@pytest.mark.parametrize("extension", ["bmp", "tiff", "webp", "gif"])
def test_any_readable_source_converts(tmp_path, extension):
    source = make_image(tmp_path / ("art." + extension))
    target = tmp_path / "art.png"

    assert image.convert_image_to_png(source, str(target)) is True
    assert opened_format(target) == "PNG"


def test_an_animated_gif_converts_from_its_first_frame(tmp_path):
    source = make_animated_gif(tmp_path / "art.gif")
    target = tmp_path / "art.png"

    assert image.convert_image_to_png(source, str(target)) is True
    with PIL.open(str(target)) as handle:
        assert handle.getpixel((0, 0)) == (255, 0, 0)


def test_converting_a_jpeg_to_jpeg_copies_it(tmp_path):
    # Already in the target format, so it transfers rather than re-encoding.
    source = make_image(tmp_path / "art.jpg")
    target = tmp_path / "copy.jpg"

    assert image.convert_image_to_jpeg(source, str(target)) is True
    assert target.read_bytes() == open(source, "rb").read()


def test_converting_a_png_to_png_copies_it(tmp_path):
    source = make_image(tmp_path / "art.png")
    target = tmp_path / "copy.png"

    assert image.convert_image_to_png(source, str(target)) is True
    assert target.read_bytes() == open(source, "rb").read()


def test_the_target_format_is_taken_from_the_extension(tmp_path):
    source = make_image(tmp_path / "art.png")
    target = tmp_path / "art.jpg"

    assert image.convert_image(source, str(target)) is True
    assert opened_format(target) == "JPEG"


def test_an_explicit_format_overrides_the_extension(tmp_path):
    source = make_image(tmp_path / "art.png")
    target = tmp_path / "art.dat"

    assert image.convert_image(
        source, str(target), image_format = config.ImageFileType.JPEG) is True
    assert opened_format(target) == "JPEG"


def test_an_undeterminable_format_reports_failure(tmp_path):
    source = make_image(tmp_path / "art.png")
    target = tmp_path / "art.dat"

    assert image.convert_image(source, str(target)) is False
    assert not target.exists()


def test_the_source_survives_conversion(tmp_path):
    source = make_image(tmp_path / "art.jpg")
    original = open(source, "rb").read()
    image.convert_image_to_png(source, str(tmp_path / "art.png"))

    assert open(source, "rb").read() == original


def test_a_missing_source_reports_failure(tmp_path):
    target = tmp_path / "art.png"

    assert image.convert_image_to_png(str(tmp_path / "absent.jpg"), str(target)) is False
    assert not target.exists()


def test_a_non_image_source_reports_failure(tmp_path):
    source = tmp_path / "art.jpg"
    source.write_text("not an image")

    assert image.convert_image_to_png(str(source), str(tmp_path / "art.png")) is False


def test_an_unwritable_target_reports_failure(tmp_path):
    source = make_image(tmp_path / "art.jpg")

    assert image.convert_image_to_png(source, str(tmp_path / "missing" / "art.png")) is False


def test_pretending_does_not_write_an_image(tmp_path):
    source = make_image(tmp_path / "art.jpg")
    target = tmp_path / "art.png"
    image.convert_image_to_png(source, str(target), pretend_run = True)

    assert not target.exists()


###########################################################
# In-memory conversion
###########################################################

def decode(result):
    return base64.b64decode(result.encode("utf-8"))


def test_jpeg_data_is_converted_to_png(tmp_path):
    # Embedded album artwork is overwhelmingly jpeg.
    source = make_image(tmp_path / "art.jpg")
    result = image.convert_image_data_to_format(
        open(source, "rb").read(), config.ImageFileType.PNG)

    assert result is not None
    assert decode(result).startswith(b"\x89PNG")


def test_png_data_is_converted_to_jpeg(tmp_path):
    source = make_image(tmp_path / "art.png")
    result = image.convert_image_data_to_format(
        open(source, "rb").read(), config.ImageFileType.JPEG)

    assert decode(result).startswith(b"\xff\xd8")


def test_converted_data_is_base64_text(tmp_path):
    source = make_image(tmp_path / "art.jpg")
    result = image.convert_image_data_to_format(
        open(source, "rb").read(), config.ImageFileType.PNG)

    assert isinstance(result, str)
    assert base64.b64encode(decode(result)).decode("utf-8") == result


def test_converted_data_reopens_as_the_target_format(tmp_path):
    import io
    source = make_image(tmp_path / "art.jpg", colour = "blue")
    result = image.convert_image_data_to_format(
        open(source, "rb").read(), config.ImageFileType.PNG)

    with PIL.open(io.BytesIO(decode(result))) as handle:
        assert handle.format == "PNG"


def test_unreadable_data_converts_to_nothing():
    assert image.convert_image_data_to_format(
        b"not an image", config.ImageFileType.PNG) is None


def test_empty_data_converts_to_nothing():
    assert image.convert_image_data_to_format(b"", config.ImageFileType.PNG) is None
