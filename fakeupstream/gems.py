"""Real gems for the fake rubygems.org: `.gem` files that `gem install` and Bundler install, the `.gemspec.rz`
specifications `gem install` reads (Ruby Marshal), and compact index lines.

A `.gem` is an uncompressed tar of `metadata.gz` (the specification as YAML), `data.tar.gz` (the files) and
`checksums.yaml.gz`. A `.gemspec.rz` is the zlib-compressed `Marshal.dump` of the specification, which RubyGems
loads with `Gem::SafeMarshal`: only the classes and instance variables it permits may appear.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import tarfile
import zlib

Deps = tuple[tuple[str, str], ...]  # (name, requirement), e.g. ("fake_hello", "~> 1.0")


def _tar(files: dict[str, bytes]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mtime = 1577836800  # 2020-01-01
            info.mode = 0o444
            info.uname = info.gname = "wheel"
            tf.addfile(info, io.BytesIO(content))
    return raw.getvalue()


def _requirement_yaml(req: str, indent: str) -> str:
    op, _, ver = req.strip().partition(" ")
    if not ver:
        op, ver = "=", op
    return (
        f'{indent}requirements:\n{indent}- - "{op}"\n{indent}  - !ruby/object:Gem::Version\n'
        f"{indent}    version: '{ver}'\n"
    )


def spec_yaml(name: str, version: str, platform: str, deps: Deps) -> bytes:
    dep_yaml = "dependencies: []\n"
    if deps:
        dep_yaml = "dependencies:\n"
        for dep, req in deps:
            dep_yaml += (
                f"- !ruby/object:Gem::Dependency\n  name: {dep}\n  requirement: !ruby/object:Gem::Requirement\n"
                + _requirement_yaml(req, "    ")
                + "  type: :runtime\n  prerelease: false\n  version_requirements: !ruby/object:Gem::Requirement\n"
                + _requirement_yaml(req, "    ")
            )
    return (
        "--- !ruby/object:Gem::Specification\n"
        f"name: {name}\nversion: !ruby/object:Gem::Version\n  version: {version}\nplatform: {platform}\n"
        "authors:\n- SlowShield tests\nbindir: bin\ncert_chain: []\ndate: 2020-01-01 00:00:00.000000000 Z\n"
        + dep_yaml
        + "description: Fake gem for SlowShield's tests.\nemail:\nexecutables: []\nextensions: []\n"
        f"extra_rdoc_files: []\nfiles:\n- lib/{name}.rb\nhomepage:\nlicenses:\n- MIT\nmetadata: {{}}\n"
        "post_install_message:\nrdoc_options: []\nrequire_paths:\n- lib\n"
        "required_ruby_version: !ruby/object:Gem::Requirement\n" + _requirement_yaml(">= 2.0", "  ") +
        "required_rubygems_version: !ruby/object:Gem::Requirement\n" + _requirement_yaml(">= 0", "  ") +
        "requirements: []\nrubygems_version: 3.6.9\nsigning_key:\nspecification_version: 4\n"
        "summary: Fake gem\ntest_files: []\n"
    ).encode()  # fmt: skip


def make_gem(name: str, version: str, platform: str = "ruby", deps: Deps = ()) -> bytes:
    """A .gem RubyGems installs: `require "<name>"` defines a constant with the version."""
    const = "".join(part.capitalize() for part in name.replace("-", "_").split("_"))
    lib = f'module {const}\n  VERSION = "{version}"\nend\n'.encode()
    metadata = gzip.compress(spec_yaml(name, version, platform, deps), mtime=0)
    data = gzip.compress(_tar({f"lib/{name}.rb": lib}), mtime=0)
    sums = "---\n" + "".join(
        f"{algo}:\n  metadata.gz: {fn(metadata).hexdigest()}\n  data.tar.gz: {fn(data).hexdigest()}\n"
        for algo, fn in (("SHA256", hashlib.sha256), ("SHA512", hashlib.sha512))
    )
    return _tar(
        {"metadata.gz": metadata, "data.tar.gz": data, "checksums.yaml.gz": gzip.compress(sums.encode(), mtime=0)}
    )


# ---- Ruby Marshal (format 4.8), just what a Gem::Specification needs ------------------------------------------


class Sym(str):
    """A Ruby Symbol."""


class _Marshal:
    def __init__(self) -> None:
        self.out = bytearray()
        self.symbols: dict[str, int] = {}

    def long(self, n: int) -> None:
        if n == 0:
            self.out.append(0)
        elif 0 < n < 123:
            self.out.append(n + 5)
        elif -124 < n < 0:
            self.out.append((n - 5) & 0xFF)
        else:  # Ruby's w_long: little-endian bytes until what is left is 0 (or -1), the count first
            buf = bytearray()
            x = n
            while True:
                buf.append(x & 0xFF)
                x >>= 8
                if x == 0:
                    self.out.append(len(buf))
                    break
                if x == -1:
                    self.out.append(256 - len(buf))
                    break
            self.out += buf

    def symbol(self, name: str) -> None:
        if name in self.symbols:
            self.out += b";"
            self.long(self.symbols[name])
            return
        self.symbols[name] = len(self.symbols)
        data = name.encode()
        self.out += b":"
        self.long(len(data))
        self.out += data

    def value(self, v: object) -> None:
        if v is None:
            self.out += b"0"
        elif v is True:
            self.out += b"T"
        elif v is False:
            self.out += b"F"
        elif isinstance(v, int):
            self.out += b"i"
            self.long(v)
        elif isinstance(v, Sym):
            self.symbol(v)
        elif isinstance(v, str):  # a UTF-8 String: the `E` instance variable says so
            data = v.encode()
            self.out += b'I"'
            self.long(len(data))
            self.out += data
            self.long(1)
            self.symbol("E")
            self.out += b"T"
        elif isinstance(v, list):
            self.out += b"["
            self.long(len(v))
            for item in v:
                self.value(item)
        elif isinstance(v, dict):
            self.out += b"{"
            self.long(len(v))
            for k, item in v.items():
                self.value(k)
                self.value(item)
        elif isinstance(v, UserMarshal):  # marshal_dump
            self.out += b"U"
            self.symbol(v.cls)
            self.value(v.data)
        elif isinstance(v, RubyObject):
            self.out += b"o"
            self.symbol(v.cls)
            self.long(len(v.ivars))
            for k, item in v.ivars.items():
                self.symbol(k)
                self.value(item)
        else:  # pragma: no cover
            raise TypeError(type(v))


class UserMarshal:
    def __init__(self, cls: str, data: object) -> None:
        self.cls, self.data = cls, data


class RubyObject:
    def __init__(self, cls: str, ivars: dict[str, object]) -> None:
        self.cls, self.ivars = cls, ivars


def dump(v: object) -> bytes:
    m = _Marshal()
    m.value(v)
    return b"\x04\x08" + bytes(m.out)


def _version(v: str) -> UserMarshal:
    return UserMarshal("Gem::Version", [v])


def _requirement(req: str) -> UserMarshal:
    op, _, ver = req.strip().partition(" ")
    if not ver:
        op, ver = "=", op
    return UserMarshal("Gem::Requirement", [[[op, _version(ver)]]])


def _platform(platform: str) -> object:
    if platform == "ruby":
        return "ruby"
    cpu, _, rest = platform.partition("-")
    os_, _, ver = rest.partition("-")
    return RubyObject("Gem::Platform", {"@cpu": cpu, "@os": os_, "@version": ver or None})


def make_gemspec_rz(name: str, version: str, platform: str = "ruby", deps: Deps = ()) -> bytes:
    """`Gem::Specification#_dump`: a Marshal string of 19 fields, inside a user-defined (`u`) object."""
    dependencies = [
        RubyObject(
            "Gem::Dependency",
            {
                "@name": dep,
                "@requirement": _requirement(req),
                "@type": Sym("runtime"),
                "@prerelease": False,
                "@version_requirements": _requirement(req),
            },
        )
        for dep, req in deps
    ]
    fields = [
        "3.6.9",  # rubygems_version
        4,  # specification_version
        name,
        _version(version),
        None,  # date
        "Fake gem",
        _requirement(">= 2.0"),
        _requirement(">= 0"),
        platform,  # original_platform
        dependencies,
        "",  # rubyforge_project
        None,  # email
        ["SlowShield tests"],
        "Fake gem for SlowShield's tests.",
        None,  # homepage
        True,  # has_rdoc
        _platform(platform),
        "MIT",
        {},
    ]
    inner = dump(fields)
    m = _Marshal()
    m.out += b"u"
    m.symbol("Gem::Specification")
    m.long(len(inner))
    m.out += inner
    return zlib.compress(b"\x04\x08" + bytes(m.out))
