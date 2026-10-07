"""The guide's HTML as Markdown, for agents: /docs/**/index.md, /llms-full.txt and the skill's references.

Stdlib only. Covers what the guide uses: headings, paragraphs, lists, tables, links, code and code blocks. Copy
buttons and other controls are left out; relative links become absolute so the files work anywhere.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from html.parser import HTMLParser

SITE = "https://slowshield.org"
_BLOCK = {"p", "ul", "ol", "li", "pre", "table", "h1", "h2", "h3", "h4", "div", "section", "article"}
_SKIP = {"button", "script", "style", "nav"}


class _Node:
    def __init__(self, tag: str, attrs: dict[str, str]) -> None:
        self.tag = tag
        self.attrs = attrs
        self.children: list[_Node | str] = []


class _Tree(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root = _Node("root", {})
        self.stack = [self.root]

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        node = _Node(tag, {k: v or "" for k, v in attrs})
        self.stack[-1].children.append(node)
        if tag not in ("br", "img", "hr", "input", "meta", "link"):
            self.stack.append(node)

    def handle_endtag(self, tag: str) -> None:
        for i in range(len(self.stack) - 1, 0, -1):
            if self.stack[i].tag == tag:
                del self.stack[i:]
                return

    def handle_data(self, data: str) -> None:
        self.stack[-1].children.append(data)


def _absolute(href: str) -> str:
    return SITE + href if href.startswith("/") else href


def _inline(node: _Node | str, pre: bool = False) -> str:
    if isinstance(node, str):
        return node if pre else re.sub(r"\s+", " ", node)
    if node.tag in _SKIP:
        return ""
    inner = "".join(_inline(c, pre) for c in node.children)
    if node.tag == "br":
        return "\n"
    if node.tag == "code" and not pre:
        text = inner.strip()
        fence = "``" if "`" in text else "`"
        return f"{fence}{text}{fence}"
    if node.tag in ("strong", "b"):
        return f"**{inner.strip()}**"
    if node.tag in ("em", "i"):
        return f"*{inner.strip()}*"
    if node.tag == "a" and node.attrs.get("href"):
        return f"[{inner.strip()}]({_absolute(node.attrs['href'])})"
    return inner


def _text(node: _Node) -> str:
    return "".join(_inline(c, pre=True) for c in node.children)


def _blocks(node: _Node, out: list[str], indent: str = "") -> None:
    """Append Markdown blocks for `node`'s children; inline runs between blocks become paragraphs."""
    run: list[str] = []

    def flush() -> None:
        text = "".join(run).strip()
        run.clear()
        if text:
            out.append(indent + text)

    for child in node.children:
        if isinstance(child, str) or child.tag not in _BLOCK | _SKIP:
            run.append(_inline(child))
            continue
        flush()
        if child.tag in _SKIP:
            continue
        tag = child.tag
        if tag in ("h1", "h2", "h3", "h4"):
            out.append("#" * int(tag[1]) + " " + "".join(_inline(c) for c in child.children).strip())
        elif tag == "p":
            text = "".join(_inline(c) for c in child.children).strip()
            if text:
                cls = child.attrs.get("class", "")
                out.append(indent + (f"*{text}*" if "doc-label" in cls else text))
        elif tag == "pre":
            code = _text(child).strip("\n")
            out.append("\n".join(indent + line for line in ["```", *code.split("\n"), "```"]))
        elif tag in ("ul", "ol"):
            items = [c for c in child.children if isinstance(c, _Node) and c.tag == "li"]
            for n, li in enumerate(items, 1):
                parts: list[str] = []
                _blocks(li, parts, indent + "   ")
                marker = f"{n}. " if tag == "ol" else "- "
                if parts:
                    parts[0] = indent + marker + parts[0].lstrip()
                out.append("\n".join(parts) if parts else indent + marker)
        elif tag == "table":
            rows = [r for r in _iter(child) if r.tag == "tr"]
            cells = [
                ["".join(_inline(c) for c in cell.children).strip().replace("|", "\\|") for cell in _cells(r)]
                for r in rows
            ]
            if cells:
                out.append("| " + " | ".join(cells[0]) + " |")
                out[-1] += "\n|" + "---|" * len(cells[0])
                for row in cells[1:]:
                    out[-1] += "\n| " + " | ".join(row) + " |"
        else:  # div, section, article, li content
            _blocks(child, out, indent)
    flush()


def _cells(row: _Node) -> list[_Node]:
    return [c for c in row.children if isinstance(c, _Node) and c.tag in ("th", "td")]


def _iter(node: _Node) -> Iterator[_Node]:
    for c in node.children:
        if isinstance(c, _Node):
            yield c
            yield from _iter(c)


def to_markdown(fragment: str) -> str:
    """Markdown for an HTML fragment of the guide."""
    tree = _Tree()
    tree.feed(fragment)
    out: list[str] = []
    _blocks(tree.root, out)
    text = "\n\n".join(b for b in out if b.strip())
    return re.sub(r"\n{3,}", "\n\n", text).strip() + "\n"
