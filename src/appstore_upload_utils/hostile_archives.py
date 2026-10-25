"""Hostile ZIP archives that every ZIP checker in the AppStore must reject.

Usage::

    from appstore_upload_utils.hostile_archives import HOSTILE_ARCHIVES
    for label, data in HOSTILE_ARCHIVES:
        ...  # run your checker against data; it must reject it

The list is the single source of truth for item 3.3 of the upload security
review (.github#13): backend, Online-IDE and Web-LaTeX all run their checker
against these archives in CI.
"""

from __future__ import annotations

import io
import os
import struct
import zipfile
import zlib

__all__ = ["HOSTILE_ARCHIVES"]


def _make_zip(entries: dict, compress: int = zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, value in entries.items():
            content, mode = value if isinstance(value, tuple) else (value, 0o100644)
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = mode << 16
            info.compress_type = compress
            z.writestr(info, content)
    return buf.getvalue()


def _build() -> list[tuple[str, bytes]]:
    cases: list[tuple[str, bytes]] = []

    def add(label: str, data: bytes) -> None:
        cases.append((label, data))

    good = _make_zip({"ok.txt": b"hello"})

    # Path traversal
    for name, label in [
        ("../../escape.txt", "zip-slip"),
        ("a/../../escape.txt", "zip-slip nested"),
        ("/tmp/absolute.txt", "absolute path"),
        ("C:/drive.txt", "drive letter"),
        ("back\\slash.txt", "backslash"),
        ("ctrl\x07char.txt", "control character"),
        ("./dot.txt", "dot component"),
        ("a//b.txt", "empty path component"),
        ("d/" * 40 + "deep.txt", "path too deeply nested"),
        ("x" * 300, "entry name too long"),
    ]:
        add(label, _make_zip({"ok.txt": b"fine", name: b"x"}))

    # Special file types
    import stat as _stat
    for mode, label in [
        (_stat.S_IFLNK | 0o777, "symlink"),
        (_stat.S_IFCHR | 0o666, "character device"),
        (_stat.S_IFBLK | 0o660, "block device"),
        (_stat.S_IFIFO | 0o644, "fifo"),
    ]:
        add(label, _make_zip({"ok.txt": b"fine", "bad": (b"/etc/passwd", mode)}))

    # Symlink + file through it
    add("symlink then file through it",
        _make_zip({"lnk": (b"/tmp", _stat.S_IFLNK | 0o777), "lnk/through.txt": b"x"}))

    # Encryption flag set in central-directory bit
    encrypted = bytearray(_make_zip({"secret.txt": b"x" * 20}))
    struct.pack_into("<H", encrypted, encrypted.rindex(b"PK\x01\x02") + 8, 0x1)
    add("encrypted entry", bytes(encrypted))

    # Unsupported compression
    add("bzip2 compression", _make_zip({"a.txt": b"x" * 200}, compress=zipfile.ZIP_BZIP2))

    # Duplicate entries (case-insensitive)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.txt", b"1")
        z.writestr("A.TXT", b"2")
    add("duplicate names (case)", buf.getvalue())

    # Structure problems
    add("empty archive", _make_zip({}))
    add("not a zip", b"MZ this is not a zip file at all" * 5)
    add("truncated zip", good[: len(good) // 2])
    add("too many entries", _make_zip({f"f{i}.txt": b"" for i in range(2001)}))

    # Decompression bomb: ~1 MiB archive, 100 MiB decompressed
    bomb = _make_zip({"big.bin": b"\x00" * (100 * 1024 * 1024)})
    add("decompression bomb (single entry)", bomb)

    many = _make_zip({f"p{i}.bin": b"\x00" * (8 * 1024 * 1024) for i in range(10)})
    add("decompression bomb (many medium entries)", many)

    # Header that lies about the uncompressed size
    lying = bytearray(_make_zip({"a.txt": b"hello world" * 100}, compress=zipfile.ZIP_STORED))
    struct.pack_into("<I", lying, lying.rindex(b"PK\x01\x02") + 24, 5)
    add("header lies about uncompressed size", bytes(lying))

    # Corrupt content (bad CRC)
    corrupt = bytearray(_make_zip({"a.txt": b"hello world" * 100}, compress=zipfile.ZIP_STORED))
    corrupt[40] ^= 0xFF
    add("corrupt content (CRC mismatch)", bytes(corrupt))

    # Overlapping entries (shared compressed bytes)
    payload = b"A" * 100_000
    local = (
        struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0, 0, 0, 0x21,
                    zlib.crc32(payload), len(payload), len(payload), 1, 0)
        + b"a" + payload
    )
    central = b"".join(
        struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0, 0, 0, 0x21,
                    zlib.crc32(payload), len(payload), len(payload), 1, 0, 0, 0, 0, 0, 0)
        + bytes([ord("a") + i])
        for i in range(5)
    )
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 5, 5, len(central), len(local), 0)
    add("overlapping entries (shared compressed bytes)", local + central + end)

    # Single file above the per-entry size limit
    add("single file too large",
        _make_zip({"big.bin": os.urandom(2 * 1024 * 1024 + 1)}, compress=zipfile.ZIP_STORED))

    return cases


HOSTILE_ARCHIVES: list[tuple[str, bytes]] = _build()
