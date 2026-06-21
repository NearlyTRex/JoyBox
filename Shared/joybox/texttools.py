# Text/substring helpers.

# Imports
import re

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
