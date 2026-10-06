"""Maven version order: a port of maven-artifact's `ComparableVersion` (the Maven 3.8 algorithm; 3.9 differs only
for unusual mixes of separators and qualifiers).

A version is split at `.`, `-` and digit/letter transitions into a tree of numbers, qualifiers and sub-lists (each
`-` and each transition opens a sub-list). Qualifiers order alpha < beta < milestone < rc (= cr) < snapshot <
"" (= ga = final = release) < sp < anything else (lexically); `a1`, `b1` and `m1` mean alpha, beta and milestone.
Trailing zeros and release qualifiers are dropped, so `1` = `1.0` = `1.0.0` = `1-ga`.
"""

from __future__ import annotations

from functools import lru_cache, total_ordering

QUALIFIERS = ("alpha", "beta", "milestone", "rc", "snapshot", "", "sp")
ALIASES = {"ga": "", "final": "", "release": "", "cr": "rc"}
RELEASE = str(QUALIFIERS.index(""))

# An item is an int, a qualifier (str) or a list of items.
Item = int | str | list


def _qualifier(value: str, followed_by_digit: bool) -> str:
    if followed_by_digit and len(value) == 1:
        value = {"a": "alpha", "b": "beta", "m": "milestone"}.get(value, value)
    return ALIASES.get(value, value)


def _rank(qualifier: str) -> str:
    """Known qualifiers by position; unknown ones after all of them, lexically (as Maven compares these strings)."""
    try:
        return str(QUALIFIERS.index(qualifier))
    except ValueError:
        return f"{len(QUALIFIERS)}-{qualifier}"


def _is_null(item: Item) -> bool:
    if isinstance(item, int):
        return item == 0
    if isinstance(item, str):
        return _rank(item) == RELEASE
    return not item


def _normalize(items: list) -> None:
    for i in range(len(items) - 1, -1, -1):
        if _is_null(items[i]):
            del items[i]
        elif not isinstance(items[i], list):
            break


def _cmp_str(a: str, b: str) -> int:
    return (a > b) - (a < b)


def compare_items(a: Item, b: Item | None) -> int:
    if isinstance(a, int):
        if b is None:
            return 0 if a == 0 else 1
        if isinstance(b, int):
            return (a > b) - (a < b)
        return 1  # a number is newer than a qualifier or a sub-list
    if isinstance(a, str):
        if b is None:
            return _cmp_str(_rank(a), RELEASE)
        if isinstance(b, str):
            return _cmp_str(_rank(a), _rank(b))
        return -1  # a qualifier is older than a number or a sub-list
    if b is None:
        return compare_items(a[0], None) if a else 0
    if isinstance(b, int):
        return -1
    if isinstance(b, str):
        return 1
    for i in range(max(len(a), len(b))):
        left = a[i] if i < len(a) else None
        right = b[i] if i < len(b) else None
        result = (
            compare_items(left, right) if left is not None else (0 if right is None else -compare_items(right, None))
        )
        if result:
            return result
    return 0


@lru_cache(maxsize=65536)
def _parse(version: str) -> tuple[Item, ...]:
    root: list = []
    current = root
    stack = [root]
    value = version.lower()
    is_digit = False
    start = 0

    def item(digit: bool, text: str) -> Item:
        return int(text) if digit else _qualifier(text, False)

    def sublist() -> None:
        nonlocal current
        new: list = []
        current.append(new)
        current = new
        stack.append(new)

    for i, ch in enumerate(value):
        if ch == ".":
            current.append(0 if i == start else item(is_digit, value[start:i]))
            start = i + 1
        elif ch == "-":
            current.append(0 if i == start else item(is_digit, value[start:i]))
            start = i + 1
            sublist()
        elif ch.isdigit():
            if not is_digit and i > start:
                current.append(_qualifier(value[start:i], True))
                start = i
                sublist()
            is_digit = True
        else:
            if is_digit and i > start:
                current.append(int(value[start:i]))
                start = i
                sublist()
            is_digit = False
    if len(value) > start:
        current.append(item(is_digit, value[start:]))
    while stack:
        _normalize(stack.pop())
    return tuple(root)


@total_ordering
class MavenVersion:
    __slots__ = ("items", "value")

    def __init__(self, value: str) -> None:
        self.value = value
        self.items = list(_parse(value))

    def compare(self, other: MavenVersion) -> int:
        return compare_items(self.items, other.items)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, MavenVersion) and self.compare(other) == 0

    def __lt__(self, other: MavenVersion) -> bool:
        return self.compare(other) < 0

    def __hash__(self) -> int:
        return hash(repr(self.items))

    def __repr__(self) -> str:
        return f"MavenVersion({self.value!r})"


@lru_cache(maxsize=65536)
def parse(value: str) -> MavenVersion:
    return MavenVersion(value.strip())


def canonical(value: str) -> str:
    """One spelling per version: versions Maven treats as equal (`1.0`, `1.0.0`, `1-ga`; `1-cr1`, `1-RC1`) give the
    same string."""
    return repr(parse(value).items)


def compare(a: str, b: str) -> int:
    return parse(a).compare(parse(b))


def is_snapshot(value: str) -> bool:
    return value.upper().endswith("-SNAPSHOT")
