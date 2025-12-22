# Imports
import re
import uuid
import urllib.parse
from datetime import datetime, timedelta
from dateutil import parser as date_parser
from dateutil.relativedelta import relativedelta

###########################################################
# ID generation utilities
###########################################################

# Generate unique ID
def generate_unique_id():
    return str(uuid.uuid4())

###########################################################
# String manipulation utilities
###########################################################

# Get enclosed substrings
def find_enclosed_substrings(string, opening_delim = "\"", closing_delim = "\""):
    pattern = rf'(?<!\\){re.escape(opening_delim)}(.*?)(?<!\\){re.escape(closing_delim)}'
    return re.findall(pattern, string)

# Split by enclosed substrings
def split_by_enclosed_substrings(string, opening_delim = "\"", closing_delim = "\""):
    split_substrings = []
    pattern = rf'(?<!\\){re.escape(opening_delim)}.*?(?<!\\){re.escape(closing_delim)}'
    substring_index = 0
    enclosed_substrings = find_enclosed_substrings(string, opening_delim, closing_delim)
    for part in re.split(pattern, string):
        split_substrings.append(part.strip())
        if substring_index < len(enclosed_substrings):
            split_substrings.append(enclosed_substrings[substring_index].strip())
            substring_index += 1
    return [part for part in split_substrings if part]

# Remove enclosed substrings
def remove_enclosed_substrings(string, opening_delim = "\"", closing_delim = "\""):
    for substring in find_enclosed_substrings(string, opening_delim, closing_delim):
        full_braced_substring = f"{opening_delim}{substring}{closing_delim}"
        string = string.replace(f" {full_braced_substring} ", " ")
        string = string.replace(f" {full_braced_substring}", " ")
        string = string.replace(f"{full_braced_substring} ", " ")
        string = string.replace(full_braced_substring, "")
    return string.strip()

# Get string similarity ratio
def get_string_similarity_ratio(string1, string2):
    try:
        from thefuzz import fuzz
        return fuzz.ratio(string1, string2)
    except:
        return 0

# Check if strings are highly similar
def are_strings_highly_similar(string1, string2):
    ratio = get_string_similarity_ratio(string1, string2)
    return (ratio >= 90)

# Check if strings are moderately similar
def are_strings_moderately_similar(string1, string2):
    ratio = get_string_similarity_ratio(string1, string2)
    return (ratio >= 80)

# Check if strings are possibly similar
def are_strings_possibly_similar(string1, string2):
    ratio = get_string_similarity_ratio(string1, string2)
    return (ratio >= 50)

# Sort strings
def sort_strings(strings):
    return sorted(strings, key=lambda item: (item, len(item)))

# Sort strings with length
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

# Trim substring from start
def trim_substring_from_start(string, substring, case_sensitive = False):
    if does_string_start_with_substring(string, substring, case_sensitive):
        return string[len(substring):]
    return string

# Trim substring from end
def trim_substring_from_end(string, substring, case_sensitive = False):
    if does_string_end_with_substring(string, substring, case_sensitive):
        return string[:-len(substring)]
    return string

# Remove string escape sequences
def remove_string_escape_sequences(string):
    pattern = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return pattern.sub("", string)

# Remove string tag sequences
def remove_string_tag_sequences(string):
    pattern = re.compile(r'</?[^>]+>')
    return pattern.sub("", string)

# Get datetime from string
def get_datetime_from_string(string, format_code):
    return datetime.strptime(string, format_code)

# Get datetime from unknown string
def get_datetime_from_unknown_string(string):

    # Try using standard and fuzzy formats first
    string = string.strip().lower()
    try:
        return date_parser.parse(string, fuzzy = True)
    except:
        pass

    # Handle other patterns
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
    return None

# Convert datetime to string
def get_string_from_datetime(date_time, format_code):
    return date_time.strftime(format_code)

# Convert datetime to string
def convert_date_string(string, old_format_code, new_format_code):
    try:
        date_time = get_datetime_from_string(string, old_format_code)
    except Exception:
        date_time = get_datetime_from_unknown_string(string)
    return get_string_from_datetime(date_time, new_format_code) if date_time else None

# Convert unknown date string
def convert_unknown_date_string(string, new_format_code):
    date_time = get_datetime_from_unknown_string(string)
    if date_time:
        return get_string_from_datetime(date_time, new_format_code)
    return None

# Get url scheme
def get_url_scheme(string):
    return urllib.parse.urlparse(string).scheme

# Get url netloc
def get_url_netloc(string):
    return urllib.parse.urlparse(string).netloc

# Get url path
def get_url_path(string):
    return urllib.parse.urlparse(string).path

# Get url params
def get_url_params(string):
    return urllib.parse.urlparse(string).params

# Get url query
def get_url_query(string):
    return urllib.parse.urlparse(string).query

# Get url fragment
def get_url_fragment(string):
    return urllib.parse.urlparse(string).fragment

# Get URL components
def get_url_components(string):
    return {
        "scheme": get_url_scheme(string),
        "netloc": get_url_netloc(string),
        "path": get_url_path(string),
        "params": get_url_params(string),
        "query": get_url_query(string),
        "fragment": get_url_fragment(string)
    }

# Encode url string
def encode_url_string(string, use_plus = False):
    if use_plus:
        return urllib.parse.quote_plus(string)
    else:
        return urllib.parse.quote(string)

# Join strings as url
def join_strings_as_url(string1, string2, allow_fragments = True):
    return urllib.parse.urljoin(string1, string2, allow_fragments = allow_fragments)

# Strip string query params
def strip_string_query_params(string):
    return urllib.parse.urlunparse(urllib.parse.urlparse(string)._replace(query=""))

# Get slug string
def get_slug_string(string):
    string = string.strip().lower()
    string = string.replace(" ", "_")
    string = re.sub(r'[^a-z0-9_]', '', string)
    string = string.replace("__", "_")
    return string
