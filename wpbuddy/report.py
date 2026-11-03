"""Thin, friendlier wrapper around markdownmaker used for scan reports."""

from pathlib import Path

from markdownmaker.document import Document
from markdownmaker.markdownmaker import (
    Bold,
    CodeBlock,
    Header,
    HeaderSubLevel,
    HorizontalRule,
    Italic,
    Link,
    OrderedList,
    Paragraph,
    UnorderedList,
)


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
        for item in items:
            self.doc.add(OrderedList((item,)))

    def code(self, text):
        self.doc.add(CodeBlock(text))

    def rule(self):
        self.doc.add(HorizontalRule())

    def write(self, path):
        # an --output under a not-yet-existing directory must just work
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.doc.write())
