# Imports
import html.parser
import operator

# Third-party imports
import pytest

# Local imports
from joybox.config import templates

ENTRY_TEMPLATES = [templates.publish_html_entry_odd, templates.publish_html_entry_even]
ENTRY_IDS = ["odd", "even"]
ENTRY_VALUES = (7, "Nintendo NES", "Super Mario Bros.", "2", "No", "Super+Mario+Bros.", "Super+Mario+Bros.")


VOID_TAGS = frozenset({"br", "hr", "img", "meta", "link", "input"})


class TagBalance(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.stack = []
        self.errors = []

    def handle_starttag(self, tag, attrs):
        if tag not in VOID_TAGS:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if self.stack and self.stack[-1] == tag:
            self.stack.pop()
        else:
            self.errors.append(tag)


def render_page(header_value, entries):
    return templates.publish_html_header % header_value + "".join(entries) + templates.publish_html_footer


@pytest.fixture
def balance():
    return TagBalance()


def test_header_takes_one_category_placeholder():
    assert "<title>Game List - Sony</title>" in templates.publish_html_header % "Sony"


@pytest.mark.parametrize("template", ENTRY_TEMPLATES, ids = ENTRY_IDS)
def test_entry_fills_cells_and_search_links_in_order(template):
    row = template % ENTRY_VALUES
    assert row.index("<td>7</td>") < row.index("<td>Nintendo NES</td>") < row.index("<td>Super Mario Bros.</td>")
    assert "gamefaqs.gamespot.com/search?game=Super+Mario+Bros." in row
    assert "mobygames.com/search/quick?q=Super+Mario+Bros." in row


@pytest.mark.parametrize("template", ENTRY_TEMPLATES, ids = ENTRY_IDS)
def test_entry_rejects_a_short_tuple(template):
    with pytest.raises(TypeError, match = "not enough arguments"):
        operator.mod(template, ENTRY_VALUES[:-1])


def test_entry_header_columns_match_entry_cells():
    columns = templates.publish_html_header.count("<th>")
    assert all(template.count("<td>") == columns for template in ENTRY_TEMPLATES)


def test_footer_takes_no_placeholders():
    assert "%" not in templates.publish_html_footer


def test_assembled_page_has_balanced_tags(balance):
    balance.feed(render_page("Nintendo", [template % ENTRY_VALUES for template in ENTRY_TEMPLATES]))
    assert balance.errors == []
    assert balance.stack == []


def test_header_alone_leaves_the_table_body_open(balance):
    balance.feed(templates.publish_html_header % "Nintendo")
    assert balance.stack == ["html", "body", "table", "tbody"]


def test_links_open_in_a_new_tab():
    row = templates.publish_html_entry_odd % ENTRY_VALUES
    assert row.count("target=\"_blank\"") == row.count("<a ")
