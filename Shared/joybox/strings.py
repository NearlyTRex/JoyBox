# Imports
import importlib
import re
import uuid
import urllib.parse
from datetime import datetime, timedelta

# Local imports
from joybox import text

# Get thefuzz.fuzz, imported on first use
def _get_fuzz():
    return importlib.import_module("thefuzz.fuzz")

# Get dateutil.parser, imported on first use
def _get_date_parser():
    return importlib.import_module("dateutil.parser")

# Get dateutil.relativedelta, imported on first use
def _get_relativedelta():
    return importlib.import_module("dateutil.relativedelta")

###########################################################
# ID generation utilities
###########################################################

# A random UUID4 as a string
def generate_unique_id():
    return str(uuid.uuid4())

###########################################################
# String manipulation utilities
###########################################################

# The string with every delimited span, delimiters included, cut out and spacing collapsed; quotes by default
def remove_enclosed_substrings(string, opening_delim = "\"", closing_delim = "\""):
    for substring in text.find_enclosed_substrings(string, opening_delim, closing_delim):
        full_braced_substring = f"{opening_delim}{substring}{closing_delim}"
        string = string.replace(f" {full_braced_substring} ", " ")
        string = string.replace(f" {full_braced_substring}", " ")
        string = string.replace(f"{full_braced_substring} ", " ")
        string = string.replace(full_braced_substring, "")
    return string.strip()

# Fuzzy match score from 0 to 100 via thefuzz; 0 when it is not installed
def get_string_similarity_ratio(string1, string2):
    try:
        fuzz = _get_fuzz()
    except ImportError:
        return 0
    return fuzz.ratio(string1, string2)

# Check if strings are highly similar
def are_strings_highly_similar(string1, string2):
    ratio = get_string_similarity_ratio(string1, string2)
    return ratio >= 90

# Check if strings are moderately similar
def are_strings_moderately_similar(string1, string2):
    ratio = get_string_similarity_ratio(string1, string2)
    return ratio >= 80

# Check if strings are possibly similar
def are_strings_possibly_similar(string1, string2):
    ratio = get_string_similarity_ratio(string1, string2)
    return ratio >= 50

# Sorted alphabetically, ties broken by length
def sort_strings(strings):
    return sorted(strings, key=lambda item: (item, len(item)))

# Sorted shortest first, then alphabetically
def sort_strings_with_length(strings):
    return sorted(strings, key=lambda item: (len(item), item))

# Check if string starts with substring
def does_string_start_with_substring(string, substring, case_sensitive = False):
    if case_sensitive:
        return string.startswith(substring)
    return string.lower().startswith(substring.lower())

# Check if string ends with substring
def does_string_end_with_substring(string, substring, case_sensitive = False):
    if case_sensitive:
        return string.endswith(substring)
    return string.lower().endswith(substring.lower())

# The string without a leading substring, case-insensitive by default; unchanged when it does not start with it
def trim_substring_from_start(string, substring, case_sensitive = False):
    if does_string_start_with_substring(string, substring, case_sensitive):
        return string[len(substring):]
    return string

# The string without a trailing substring, case-insensitive by default; unchanged when it does not end with it
def trim_substring_from_end(string, substring, case_sensitive = False):
    if not substring:
        return string
    if does_string_end_with_substring(string, substring, case_sensitive):
        return string[:-len(substring)]
    return string

# The string with ANSI terminal escape codes stripped
def remove_string_escape_sequences(string):
    pattern = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return pattern.sub("", string)

# The string with HTML or XML tags stripped, keeping their text
def remove_string_tag_sequences(string):
    pattern = re.compile(r'</?[^>]+>')
    return pattern.sub("", string)

# Parse with a strptime format; raises ValueError on a mismatch
def get_datetime_from_string(string, format_code):
    return datetime.strptime(string, format_code)

# Parse relative phrases like "3 days ago" or "yesterday", else any format dateutil can fuzzily read
# None when nothing parses
def get_datetime_from_unknown_string(string):

    # Imports
    date_parser = _get_date_parser()
    relativedelta = _get_relativedelta().relativedelta

    # Relative phrases first, since fuzzy parsing reads "3 days ago" as the 3rd
    string = string.strip().lower()
    patterns = [
        (r"(\d+)\s+days?\s+ago", lambda x: datetime.now() - timedelta(days=int(x))),
        (r"(\d+)\s+weeks?\s+ago", lambda x: datetime.now() - timedelta(weeks=int(x))),
        (r"(\d+)\s+months?\s+ago", lambda x: datetime.now() - relativedelta(months=int(x))),
        (r"(\d+)\s+years?\s+ago", lambda x: datetime.now() - relativedelta(years=int(x))),
        (r"yesterday", lambda _: datetime.now() - timedelta(days=1)),
        (r"today", lambda _: datetime.now()),
        (r"an hour ago", lambda _: datetime.now() - timedelta(hours=1)),
    ]
    for pattern, handler in patterns:
        match = re.match(pattern, string)
        if match:
            return handler(match.group(1) if match.groups() else None)

    # Standard and fuzzy formats
    try:
        return date_parser.parse(string, fuzzy = True)
    except (ValueError, OverflowError):
        return None

# Convert datetime to string
def get_string_from_datetime(date_time, format_code):
    return date_time.strftime(format_code)

# Reformat a date string from one strptime format to another, falling back to fuzzy parsing; None when unparseable
def convert_date_string(string, old_format_code, new_format_code):
    try:
        date_time = get_datetime_from_string(string, old_format_code)
    except ValueError:
        date_time = get_datetime_from_unknown_string(string)
    return get_string_from_datetime(date_time, new_format_code) if date_time else None

# Reformat a date in any recognizable format into new_format_code; None when unparseable
def convert_unknown_date_string(string, new_format_code):
    date_time = get_datetime_from_unknown_string(string)
    if date_time:
        return get_string_from_datetime(date_time, new_format_code)
    return None

# Parse timestamp string to unix timestamp
def parse_timestamp(timestamp_string):
    if not timestamp_string:
        return 0
    try:
        if "T" in timestamp_string:
            if "." in timestamp_string:
                timestamp_string = timestamp_string.split(".")[0] + "Z"
            dt = datetime.strptime(timestamp_string.replace("Z", "+0000"), "%Y-%m-%dT%H:%M:%S%z")
            return int(dt.timestamp())
        dt = datetime.strptime(timestamp_string.strip(), "%Y-%m-%d %H:%M:%S")
        return int(dt.timestamp())
    except ValueError:
        return 0

# Scheme part of a url, such as https; empty when absent
def get_url_scheme(string):
    return urllib.parse.urlparse(string).scheme

# Host and port part of a url; empty when absent
def get_url_netloc(string):
    return urllib.parse.urlparse(string).netloc

# Path part of a url, without query or fragment
def get_url_path(string):
    return urllib.parse.urlparse(string).path

# Semicolon parameters of the last path segment of a url; usually empty
def get_url_params(string):
    return urllib.parse.urlparse(string).params

# Query string of a url, without the leading ?
def get_url_query(string):
    return urllib.parse.urlparse(string).query

# Fragment of a url, without the leading #
def get_url_fragment(string):
    return urllib.parse.urlparse(string).fragment

# A url split into a dict of scheme, netloc, path, params, query and fragment
def get_url_components(string):
    return {
        "scheme": get_url_scheme(string),
        "netloc": get_url_netloc(string),
        "path": get_url_path(string),
        "params": get_url_params(string),
        "query": get_url_query(string),
        "fragment": get_url_fragment(string)
    }

# Percent-encode text for a url; use_plus turns spaces into + for query strings
def encode_url_string(string, use_plus = False):
    if use_plus:
        return urllib.parse.quote_plus(string)
    return urllib.parse.quote(string)

# Resolve string2 against string1 as a base url, as a browser would
def join_strings_as_url(string1, string2, allow_fragments = True):
    return urllib.parse.urljoin(string1, string2, allow_fragments = allow_fragments)

# The url with its query string removed, keeping any fragment
def strip_string_query_params(string):
    return urllib.parse.urlunparse(urllib.parse.urlparse(string)._replace(query=""))

# Lowercase identifier from text: spaces to underscores, only a-z, 0-9 and single underscores kept
def get_slug_string(string):
    string = string.strip().lower()
    string = string.replace(" ", "_")
    string = re.sub(r'[^a-z0-9_]', '', string)
    string = re.sub(r'_+', '_', string)
    return string.strip("_")
