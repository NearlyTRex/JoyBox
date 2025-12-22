# Imports
import textwrap

# Local imports
import config

###########################################################
# Text processing utilities
###########################################################

# Capitalize text
def capitalize_text(text):
    if len(text) == 0:
        return ""
    elif len(text) == 1:
        return text.upper()
    else:
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

# Wrap text to lines
def wrap_text_to_lines(text, width = 80, spacer = "."):
    wrapped_lines = []
    text_lines = text.split("\n")
    for index, line in enumerate(text_lines):
        for wrapped_line in textwrap.wrap(line.strip(), width=width):
            wrapped_lines.append(wrapped_line)
        if index < len(text_lines) - 1 and len(spacer):
            wrapped_lines.append(spacer)
    return wrapped_lines

# Clean rich text
def clean_rich_text(text):
    new_text = text
    try:
        import unidecode
        new_text = unidecode.unidecode(new_text)
    except:
        pass
    for old, new in config.rich_text_replacements.items():
        new_text = new_text.replace(old, new)
    new_text = new_text.encode("ascii", "ignore").decode()
    return new_text.strip()

# Clean web text
def clean_web_text(text):
    new_text = clean_rich_text(text)
    for old, new in config.web_text_replacements.items():
        new_text = new_text.replace(old, new)
    return new_text

# Extract web text
def extract_web_text(text):
    try:
        import html_text
        return html_text.extract_text(text)
    except:
        return None
