# Interactive component selection for bootstrap.py --interactive

###########################################################
# Parsing
###########################################################

# Turn a selection like "1 3-5 steam -wine" into component names.
# Blank or "all" means everything; a leading "-" leaves an entry out.
def parse_selection(text, names):
    tokens = text.replace(",", " ").split()
    includes = []
    excludes = []
    for token in tokens:
        target = excludes if token.startswith("-") else includes
        token = token.lstrip("-")
        if not token:
            raise ValueError("'-' needs a number or name after it")
        target.extend(resolve_token(token, names))
    if not includes:
        includes = list(names)
    return [name for name in names if name in includes and name not in excludes]

def resolve_token(token, names):
    if token.lower() == "all":
        return list(names)
    if token in names:
        return [token]
    if "-" in token:
        start, end = token.split("-", 1)
        first, last = resolve_number(start, names), resolve_number(end, names)
        if first > last:
            raise ValueError(f"'{token}' is a backwards range")
        return names[first - 1:last]
    return [names[resolve_number(token, names) - 1]]

def resolve_number(token, names):
    if not token.isdigit():
        raise ValueError(f"'{token}' is not a component number or name")
    number = int(token)
    if number < 1 or number > len(names):
        raise ValueError(f"{number} is out of range (1-{len(names)})")
    return number

###########################################################
# Prompting
###########################################################

# Ask which components to process. Returns the chosen names, or None to quit.
def choose_components(names, action = "setup", read = input, write = print):
    while True:
        write(f"Components available for {action}:")
        width = len(str(len(names)))
        for number, name in enumerate(names, 1):
            write(f"  {number:>{width}}) {name}")
        write("Enter numbers, ranges or names (e.g. '1 3-5 steam'), prefix with '-' to leave out,")
        write("press Enter for all of them, or 'q' to quit.")
        answer = read("Selection: ").strip()
        if answer.lower() in ("q", "quit"):
            return None
        try:
            chosen = parse_selection(answer, names)
        except ValueError as error:
            write(f"Invalid selection: {error}")
            continue
        if not chosen:
            write("Nothing selected.")
            continue
        write(f"Will {action} {len(chosen)} of {len(names)}: {', '.join(chosen)}")
        confirm = None
        while confirm not in ("", "y", "yes", "n", "no", "q", "quit"):
            confirm = read("Continue? [Y/n/q] ").strip().lower()
        if confirm in ("", "y", "yes"):
            return chosen
        if confirm in ("q", "quit"):
            return None
