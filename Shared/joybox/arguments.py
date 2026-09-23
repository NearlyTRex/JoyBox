# Imports
import os, os.path
import argparse
import enum

# Local imports
import joybox.config as config
import joybox.logger as logger
import joybox.paths as paths

# Enum parser
def parse_enum_value(enum_type, enum_value):
    if isinstance(enum_value, enum_type):
        return enum_value
    else:
        try:
            return enum_type.from_string(enum_value)
        except Exception as e:
            return None

# Enum argparse action
class EnumArgparseAction(argparse.Action):
    def __init__(self, option_strings, dest, type, **kwargs):
        self.enum_type = type
        super().__init__(option_strings, dest, type=str, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        if isinstance(values, list):
            result = [parse_enum_value(self.enum_type, v) for v in values]
        else:
            result = parse_enum_value(self.enum_type, values)
        setattr(namespace, self.dest, result)

# Help formatter
# Keeps the epilog's line breaks, since examples are commands, and shows a
# default only when there is one worth reading
class HelpFormatter(argparse.RawDescriptionHelpFormatter, argparse.ArgumentDefaultsHelpFormatter):
    def _get_help_string(self, action):
        if action.default in (None, False, [], "") or action.default is argparse.SUPPRESS:
            return action.help
        return super()._get_help_string(action)

# Argument parser
class ArgumentParser:
    def __init__(
        self,
        description,
        details = None,
        examples = None,
        notes = None,
        see_also = None,
        section = None):
        self.description = description
        self.details = details
        self.examples = list(examples or [])
        self.notes = list(notes or [])
        self.see_also = list(see_also or [])
        self.section = section
        self.parser = argparse.ArgumentParser(
            description = description,
            epilog = self._build_epilog(),
            formatter_class = HelpFormatter)
        self._target = self.parser
        self._groups = []
        self._warned_unknown = set()

    #################################################

    # Build the text shown after the options in -h
    def _build_epilog(self):
        lines = []
        if self.details:
            lines += [self.details.strip(), ""]
        if self.examples:
            lines.append("examples:")
            for title, command in self.examples:
                lines += ["  # %s" % title, "  %s" % command, ""]
        if self.notes:
            lines.append("notes:")
            lines += ["  - %s" % note for note in self.notes]
            lines.append("")
        if self.see_also:
            lines.append("see also: %s" % ", ".join(self.see_also))
        return "\n".join(lines).strip() or None

    # Start a titled group; arguments added after this belong to it
    def add_group(self, title):
        group = self.parser.add_argument_group(title)
        self._groups.append(group)
        self._target = group
        return group

    #################################################

    # Expand long-option names so hyphen and underscore forms are interchangeable
    # (e.g. --pretend_run also accepts --pretend-run, and vice versa). This avoids
    # silently dropping a mistyped safety flag like --pretend-run.
    def _expand_arg_aliases(self, args):
        arg_names = list(args if isinstance(args, tuple) else (args,))
        aliases = []
        for name in arg_names:
            if not name.startswith("--"):
                continue
            if "_" in name:
                alt = name.replace("_", "-")
            elif "-" in name[2:]:
                alt = "--" + name[2:].replace("-", "_")
            else:
                continue
            if alt not in arg_names and alt not in aliases:
                aliases.append(alt)
        return tuple(arg_names) + tuple(aliases)

    # Add an argument to the current group, remembering what was declared
    # rather than the aliases, and the description before any decoration
    def _add_argument(self, args, description, **kwargs):
        declared = tuple(args if isinstance(args, tuple) else (args,))
        action = self._target.add_argument(*self._expand_arg_aliases(declared), **kwargs)
        action.joybox_flags = declared
        action.joybox_description = description
        return action

    #################################################

    # Parse arguments
    def parse_args(self):
        return self.parser.parse_args()

    # Parse known arguments
    def parse_known_args(self):
        args, unknown = self.parser.parse_known_args()
        flagged = [u for u in unknown if u.startswith("-") and u not in self._warned_unknown]
        for u in flagged:
            self._warned_unknown.add(u)
        if flagged:
            logger.log_warning("Ignoring unrecognized argument(s): %s" % " ".join(flagged))
        return args, unknown

    # Check if the given name is a known argument
    def is_known_argument(self, name):
        return any(action.dest == name for action in self.parser._actions)

    #################################################

    # Describe the parser as plain data, for generating documentation
    def describe(self):
        def describe_action(action):
            flags = getattr(action, "joybox_flags", tuple(action.option_strings))
            default = action.default
            if isinstance(default, enum.Enum):
                default = str(default)
            elif isinstance(default, list):
                default = [str(value) for value in default]
            return {
                "flags": list(flags),
                "dest": action.dest,
                "positional": not action.option_strings,
                "takes_value": action.nargs != 0,
                "required": bool(action.required) or (not action.option_strings and action.nargs != "?"),
                "description": getattr(action, "joybox_description", action.help),
                "default": default,
                "choices": getattr(action, "joybox_choices", None) or ([str(choice) for choice in action.choices] if action.choices else None),
            }
        def is_documented(action):
            return not isinstance(action, argparse._HelpAction)
        groups = [{
            "title": None,
            "options": [describe_action(action) for action in self.parser._actions
                if is_documented(action) and not any(action in group._group_actions for group in self._groups)],
        }]
        for group in self._groups:
            groups.append({
                "title": group.title,
                "options": [describe_action(action) for action in group._group_actions if is_documented(action)],
            })
        return {
            "description": self.description,
            "details": self.details,
            "examples": [list(example) for example in self.examples],
            "notes": self.notes,
            "see_also": self.see_also,
            "section": self.section,
            "groups": [group for group in groups if group["options"]],
        }

    #################################################

    # Get path
    def get_path(self, argname):
        if not self.is_known_argument(argname):
            return None
        args, unknown = self.parse_known_args()
        args_dict = vars(args)
        if argname not in args_dict.keys():
            return None
        if not args_dict[argname]:
            return None
        virt_path = args_dict[argname]
        real_path = os.path.realpath(virt_path)
        return real_path

    # Get checked path
    def get_checked_path(self, argname):
        path = self.get_path(argname)
        if not paths.does_path_exist(path):
            logger.log_error("Path '%s' does not exist" % path, quit_program = True)
        return path

    #################################################

    # Add string argument
    def add_string_argument(
        self,
        args,
        default = None,
        required = False,
        description = None):
        is_positional = not args[0].startswith("-") if isinstance(args, tuple) else not args.startswith("-")
        if is_positional:
            return self._add_argument(args, description,
                default = default,
                nargs = "?" if default is not None else None,
                type = str,
                help = description)
        return self._add_argument(args, description,
            default = default,
            required = required,
            type = str,
            help = description)

    # Add string list argument
    def add_string_list_argument(
        self,
        args,
        default = None,
        required = False,
        description = None):
        return self._add_argument(args, description,
            action = "append",
            default = default,
            required = required,
            type = str,
            help = description)

    # Add integer argument
    def add_integer_argument(
        self,
        args,
        default = None,
        required = False,
        description = None):
        is_positional = not args[0].startswith("-") if isinstance(args, tuple) else not args.startswith("-")
        if is_positional:
            return self._add_argument(args, description,
                default = default,
                nargs = "?" if default is not None else None,
                type = int,
                help = description)
        return self._add_argument(args, description,
            default = default,
            required = required,
            type = int,
            help = description)

    # Add boolean argument
    def add_boolean_argument(
        self,
        args,
        description = None):
        return self._add_argument(args, description,
            action = "store_true",
            help = description)

    # Add enum argument
    def add_enum_argument(
        self,
        args,
        arg_type = None,
        default = None,
        description = None,
        allow_multiple = False):
        enum_values = arg_type.values()
        quoted_enum_values = [f"'{value}'" for value in enum_values]
        if allow_multiple:
            if default is not None:
                if not isinstance(default, list):
                    default = [default]
            else:
                default = []
            return self._add_argument(args, description,
                default = default,
                type = arg_type,
                action = EnumArgparseAction,
                choices = arg_type.values(),
                help = f"{description}.\nAllowed values are [{', '.join(quoted_enum_values)}]",
                nargs = "+",
                metavar = "")
        return self._add_argument(args, description,
            default = default,
            type = arg_type,
            action = EnumArgparseAction,
            choices = arg_type.values(),
            help = f"{description}.\nAllowed values are [{', '.join(quoted_enum_values)}]",
            metavar = "")

    # Add enum list argument
    def add_enum_list_argument(
        self,
        args,
        arg_type = None,
        description = None):
        enum_values = arg_type.values()
        quoted_enum_values = [f"'{value}'" for value in enum_values]
        action = self._add_argument(args, description,
            default = None,
            type = str,
            help = f"{description} (comma delimited).\nAllowed values are [{', '.join(quoted_enum_values)}]")
        action.joybox_choices = [str(value) for value in enum_values]
        return action

    #################################################

    # Add input path argument
    def add_input_path_argument(self, args = ("-i", "--input_path"), default = None, required = False, description = "Input path"):
        self.add_string_argument(
            args = args,
            default = default,
            required = required,
            description = description)

    # Add output path argument
    def add_output_path_argument(self, args = ("-o", "--output_path"), default = None, required = False, description = "Output path"):
        self.add_string_argument(
            args = args,
            default = default,
            required = required,
            description = description)

    # Get input path
    def get_input_path(self, check_exists = True):
        if check_exists:
            return self.get_checked_path("input_path")
        return self.get_path("input_path")

    # Get output path
    def get_output_path(self, check_exists = True):
        if check_exists:
            return self.get_checked_path("output_path")
        return self.get_path("output_path")

    #################################################

    # Add game supercategory argument
    def add_game_supercategory_argument(self, args = ("-u", "--game_supercategory"), description = "Game supercategory type"):
        self.add_enum_argument(
            args = args,
            arg_type = config.Supercategory,
            default = config.Supercategory.ROMS,
            description = description)

    # Add game category argument
    def add_game_category_argument(self, args = ("-c", "--game_category"), description = "Game category type"):
        self.add_enum_argument(
            args = args,
            arg_type = config.Category,
            description = description)

    # Add game subcategory argument
    def add_game_subcategory_argument(self, args = ("-s", "--game_subcategory"), description = "Game subcategory type"):
        self.add_enum_argument(
            args = args,
            arg_type = config.Subcategory,
            description = description)

    # Add game name argument
    def add_game_name_argument(self, args = ("-n", "--game_name"), description = "Game name"):
        self.add_string_argument(
            args = args,
            description = description)

    # Add game offset argument
    def add_game_offset_argument(self, args = ("-g", "--game_offset"), description = "Game offset"):
        self.add_string_argument(
            args = args,
            description = description)

    # Get selected supercategories
    def get_selected_supercategories(self, argname = "game_supercategory"):
        args, unknown = self.parse_known_args()
        supercategories = []
        supercategory_arg = getattr(args, argname, None)
        if supercategory_arg:
            supercategories = [supercategory_arg]
        else:
            supercategories = config.Supercategory.members()
        return supercategories

    # Get selected categories
    def get_selected_categories(self, argname = "game_category"):
        args, unknown = self.parse_known_args()
        categories = []
        category_arg = getattr(args, argname, None)
        if category_arg:
            categories = [category_arg]
        else:
            categories = config.Category.members()
        return categories

    # Get selected subcategories
    def get_selected_subcategories(
        self,
        category_argname = "game_category",
        subcategory_argname = "game_subcategory"):
        args, unknown = self.parse_known_args()
        subcategory_map = {}
        for category in self.get_selected_categories(argname = category_argname):
            subcategories = []
            subcategory_arg = getattr(args, subcategory_argname, None)
            if subcategory_arg:
                subcategories = [subcategory_arg]
            else:
                subcategories = config.subcategory_map.get(category, [])
            subcategory_map[category] = subcategories
        return subcategory_map

    #################################################

    # Add common arguments
    def add_common_arguments(self):
        previous_target = self._target
        self.add_group("Common options")
        self.add_boolean_argument(
            args = ("-v", "--verbose"),
            description = "Enable verbose mode")
        self.add_boolean_argument(
            args = ("-p", "--pretend_run"),
            description = "Do a pretend run with no permanent changes")
        self.add_boolean_argument(
            args = ("-x", "--exit_on_failure"),
            description = "Enable exit on failure mode")
        self.add_boolean_argument(
            args = ("--no-preview",),
            description = "Skip the preview confirmation prompt")
        self._target = previous_target

    #################################################
