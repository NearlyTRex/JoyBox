# Imports
import importlib
import importlib.util
import re
import textwrap

# Local imports
from joybox import config

# Get unidecode, imported on first use
def _get_unidecode():
    return importlib.import_module("unidecode")

# Get html_text, imported on first use
def _get_html_text():
    return importlib.import_module("html_text")

###########################################################
# Text processing utilities
###########################################################

# Title-case each word by its first letter, leaving filler words after the first lowercase as written
def capitalize_text(text):
    if len(text) == 0:
        return ""
    if len(text) == 1:
        return text.upper()
    words = []
    for index, word in enumerate(text.split(" ")):
        for filler_word in config.filler_words:
            if index != 0 and word.lower() == filler_word.lower():
                words.append(word)
                break
        else:
            if len(word) == 1:
                words.append(word[0].upper())
            elif len(word) >= 2:
                words.append(word[0].upper() + word[1:])
    return " ".join(words)

# Lines wrapped to width, with a spacer line between the original paragraphs
def wrap_text_to_lines(text, width = 80, spacer = "."):
    wrapped_lines = []
    text_lines = text.split("\n")
    for index, line in enumerate(text_lines):
        for wrapped_line in textwrap.wrap(line.strip(), width=width):
            wrapped_lines.append(wrapped_line)
        if index < len(text_lines) - 1 and spacer:
            wrapped_lines.append(spacer)
    return wrapped_lines

# Plain ASCII text: transliterated by unidecode when installed, typographic characters replaced, the rest dropped
def clean_rich_text(text):
    new_text = text
    # unidecode is optional; without it non-ascii is dropped below
    if importlib.util.find_spec("unidecode"):
        unidecode = _get_unidecode()
        new_text = unidecode.unidecode(new_text)
    for old, new in config.rich_text_replacements.items():
        new_text = new_text.replace(old, new)
    new_text = new_text.encode("ascii", "ignore").decode()
    return new_text.strip()

# Rich text cleanup plus the configured web text replacements
def clean_web_text(text):
    new_text = clean_rich_text(text)
    for old, new in config.web_text_replacements.items():
        new_text = new_text.replace(old, new)
    return new_text

# Readable text from an HTML document via html_text; None when it is not installed
def extract_web_text(text):
    try:
        html_text = _get_html_text()
    except ImportError:
        return None
    return html_text.extract_text(text)

###########################################################
# Substring utilities
###########################################################

# Find substrings enclosed by the given delimiters (ignoring escaped delimiters)
def find_enclosed_substrings(string, opening_delim = "\"", closing_delim = "\""):
    pattern = rf'(?<!\\){re.escape(opening_delim)}(.*?)(?<!\\){re.escape(closing_delim)}'
    return re.findall(pattern, string)

# Split a string, preserving substrings enclosed by the given delimiters as single parts
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
