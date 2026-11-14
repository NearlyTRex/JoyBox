# Local imports
from joybox import logger

# Curated tag fields that can be read, written, and force-overridden.
# Mirrors the values of AudioMetadata.text_mappings / mp4_tag_mappings.
curated_tag_fields = [
    "title",
    "artist",
    "album",
    "year",
    "genre",
    "album_artist",
    "track_number",
    "disc_number",
    "bpm",
    "key",
    "conductor"
]

# Parse forced tag overrides given as field=value entries
def parse_force_tags(set_values):
    force_tags = {}
    for entry in set_values or []:
        if "=" not in entry:
            logger.log_error(f"Invalid --set value (expected field=value): {entry}")
            return None
        field, value = entry.split("=", 1)
        field = field.strip()
        if field not in curated_tag_fields:
            logger.log_error(f"Unknown tag field '{field}'. Allowed fields: {', '.join(curated_tag_fields)}")
            return None
        force_tags[field] = value
    return force_tags
