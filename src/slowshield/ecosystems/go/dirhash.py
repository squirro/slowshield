"""The Go checksum database's `h1:` hash of a module zip (golang.org/x/mod/sumdb/dirhash.HashZip, Hash1).

h1 = base64(sha256 of the summary), where the summary has one line `<sha256 hex>  <name>\\n` per file in the zip,
sorted by name. It hashes the files inside the zip, not the zip's bytes, so it needs the whole body.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import zipfile
from pathlib import Path

MAX_UNZIPPED = 500 << 20  # golang.org/x/mod/zip.MaxZipFile: a module's files, uncompressed
_UTF8 = 0x800  # general purpose flag: the stored name is UTF-8 (otherwise Go keeps the raw bytes)


def hash_zip(path: Path) -> str:
    total = 0
    summary = hashlib.sha256()
    with zipfile.ZipFile(path) as zf:
        # Go hashes the raw stored names, in byte order; Python decodes names without the UTF-8 flag as cp437.
        entries: dict[bytes, zipfile.ZipInfo] = {}
        names: list[bytes] = []
        for info in zf.infolist():
            raw = info.filename.encode("utf-8" if info.flag_bits & _UTF8 else "cp437")
            entries[raw] = info  # like Go's map: a duplicate name hashes the last entry twice
            names.append(raw)
        for raw in sorted(names):
            if b"\n" in raw:
                raise ValueError("file name with a newline")
            h = hashlib.sha256()
            with zf.open(entries[raw]) as fh:
                while chunk := fh.read(1 << 16):
                    total += len(chunk)
                    if total > MAX_UNZIPPED:
                        raise ValueError("more than 500 MB uncompressed")
                    h.update(chunk)
            summary.update(h.hexdigest().encode() + b"  " + raw + b"\n")
    return "h1:" + base64.b64encode(summary.digest()).decode()


def zip_problem(path: Path, expected: str) -> str | None:
    """None when the zip at `path` has the `expected` h1; otherwise what is wrong with it."""
    try:
        got = hash_zip(path)
    except (zipfile.BadZipFile, ValueError, OSError, EOFError, NotImplementedError) as exc:
        return f"not a valid module zip ({exc})"
    return None if hmac.compare_digest(got, expected) else "h1 does not match the Go checksum database"
