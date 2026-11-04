"""Thin, friendlier wrapper around markdownmaker used for scan reports."""

import re
from pathlib import Path

from markdownmaker.document import Document
from markdownmaker.markdownmaker import (
    CodeBlock,
    Header,
    HeaderSubLevel,
    HorizontalRule,
    OrderedList,
    Paragraph,
    UnorderedList,
)

# markdown-active characters that must render literally when they come from
# the scanned site or scraped databases (P2-6)
_MD_SPECIAL = re.compile(r"([`*_\[\]])")
_MD_LINE_START = re.compile(r"^(\s*)([#>\-+])")


def escape_md(text):
    """Escape markdown syntax characters in target-controlled text.

    Advisory names, header values, server strings, robots entries and
    operator slugs must never reformat the report (an unescaped '*' in a
    plugin slug once bolded half a line). Fenced code bodies are NOT passed
    through this - they stay raw evidence; Report.code guards their fences
    instead.
    """
    if not text:
        return text
    text = _MD_SPECIAL.sub(r"\\\1", str(text))
    return _MD_LINE_START.sub(r"\1\\\2", text)


def _md_url(url):
    """A markdown-safe link destination (spaces/parens break [text](url))."""
    return str(url).replace(" ", "%20").replace("(", "%28").replace(")", "%29")


class Report:
    def __init__(self):
        self.doc = Document()

    def title(self, text):
        self.doc.add(Header(text))

    def section(self, text):
        with HeaderSubLevel(self.doc):
            self.doc.add(Header(text))

    def paragraph(self, text=""):
        self.doc.add(Paragraph(text) if not isinstance(text, str) else text)

    def bullets(self, items):
        if items:
            self.doc.add(UnorderedList(tuple(items)))

    def numbered(self, items):
        """One ordered list for the whole iterable - adding an OrderedList
        per item rendered every entry as '1.'."""
        if items:
            self.doc.add(OrderedList(tuple(items)))

    def code(self, text):
        """Fenced code block. Bodies stay raw (they are evidence), but a
        body line of ``` would close the fence early and leak the rest into
        the report - use a longer fence than any backtick run inside."""
        text = str(text)
        longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
        if longest >= 3:
            fence = "`" * (longest + 1)
            self.doc.add(f"{fence}\n{text}\n{fence}")
        else:
            self.doc.add(CodeBlock(text))

    def prepend(self, other):
        """Splice another report's nodes right after the title (F-10).

        markdownmaker only appends; the executive summary must sit at the
        top, so it is built in a separate document and inserted after the
        first node (the H1) preserving each node's header level.
        """
        nodes = list(other.doc.nodes)
        if nodes:
            self.doc.nodes[1:1] = nodes

    def rule(self):
        self.doc.add(HorizontalRule())

    def write(self, path):
        # an --output under a not-yet-existing directory must just work
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.doc.write())
