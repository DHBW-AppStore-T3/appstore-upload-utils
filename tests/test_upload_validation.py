"""Tests for appstore_upload_utils.upload_validation.

Standalone — no FastAPI, no database, no app.* imports. These cover the
content-inspection contract shared by backend, Online-IDE and Web-LaTeX.
"""

from __future__ import annotations

import io
import stat
import zipfile

import pytest

from appstore_upload_utils.upload_validation import UploadRejected, inspect_upload

try:
    from tests.upload_samples import jpeg, png
except ImportError:
    from upload_samples import jpeg, png

PNG = png()
JPEG = jpeg()
PDF = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF\n"


def make_zip(entries: dict, compress: int = zipfile.ZIP_DEFLATED) -> bytes:
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


def rejected_code(name: str, data: bytes, exts: list | None = None) -> str:
    with pytest.raises(UploadRejected) as exc:
        inspect_upload(name, data, exts)
    return exc.value.code


# ---------------------------------------------------------------- ZIP

def test_good_zip_passes_and_reports_its_size():
    data = make_zip({"aufgaben/": b"", "aufgaben/A1.java": b"class A {}", "aufgaben/A2.java": b"class B {}"})
    result = inspect_upload("tasks.zip", data, ["zip"])
    assert result.content_type == "application/zip"
    assert result.zip_unpacked_bytes > 0
    assert result.zip_entries >= 2


@pytest.mark.parametrize("name,code", [
    ("../evil", "zip_path_traversal"),
    ("/etc/passwd", "zip_absolute_path"),
    ("sub/../../../etc/x", "zip_path_traversal"),
])
def test_zip_with_dangerous_paths_is_rejected(name, code):
    assert rejected_code("x.zip", make_zip({name: b"x"})) == code


def test_member_names_with_backslashes_are_refused():
    assert rejected_code("x.zip", make_zip({"back\\slash.txt": b"x"})) == "zip_bad_name"


@pytest.mark.parametrize("mode", [stat.S_IFLNK | 0o777, stat.S_IFBLK | 0o660, stat.S_IFCHR | 0o660])
def test_zip_with_links_or_device_files_is_rejected(mode):
    assert rejected_code("x.zip", make_zip({"x": (b"x", mode)})) == "zip_special_file"


def test_zip_with_unsupported_compression_is_rejected():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_BZIP2) as z:
        z.writestr("x.txt", b"hello")
    assert rejected_code("x.zip", buf.getvalue()) == "zip_compression"


def test_empty_zip_is_rejected():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w"):
        pass
    assert rejected_code("x.zip", buf.getvalue()) == "zip_empty"


def test_decompression_bomb_hits_total_limit():
    # 33 entries × 2 MiB = 66 MiB > 64 MiB limit
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for i in range(33):
            info = zipfile.ZipInfo(f"{i}.bin")
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, b"\x00" * (2 * 1024 * 1024))
    assert rejected_code("bomb.zip", buf.getvalue()) == "zip_bomb"


def test_zip_content_under_wrong_extension_is_a_mismatch():
    assert rejected_code("x.pdf", make_zip({"x.pdf": PDF})) == "content_type_mismatch"


def test_not_a_zip_with_a_zip_name_is_rejected():
    assert rejected_code("x.zip", b"this is not a zip") == "content_type_mismatch"


def test_programs_are_refused_unless_listed():
    assert rejected_code("x.exe", b"MZ" + b"\x00" * 200) == "executable_not_allowed"
    assert rejected_code("x.elf", b"\x7fELF" + b"\x00" * 60) == "executable_not_allowed"


def test_a_program_passes_when_the_app_lists_its_extension():
    result = inspect_upload("x.exe", b"MZ" + b"\x00" * 200, ["exe"])
    assert result.content_type is not None


def test_archive_formats_that_cannot_be_inspected_need_an_explicit_extension():
    gz = b"\x1f\x8b" + b"\x00" * 20
    assert rejected_code("x.gz", gz) == "archive_not_inspectable"
    result = inspect_upload("x.gz", gz, ["gz"])
    assert result.content_type is not None


# ---------------------------------------------------------------- type matching

def test_pdf_images_and_text_pass_with_correct_extension():
    assert inspect_upload("x.pdf", PDF, ["pdf"]).content_type == "application/pdf"
    assert inspect_upload("x.png", PNG, ["png"]).content_type == "image/png"
    assert inspect_upload("x.txt", b"Hello world\n", ["txt"]).content_type == "text/plain"


def test_claimed_type_must_match_the_bytes():
    assert rejected_code("x.pdf", PNG, ["pdf"]) == "content_type_mismatch"
    assert rejected_code("x.png", PDF, ["png"]) == "content_type_mismatch"


def test_text_files_must_be_text():
    assert rejected_code("x.txt", b"text\x00binary", ["txt"]) == "content_type_mismatch"


# ---------------------------------------------------------------- SVG

def test_svg_with_script_is_rejected():
    svg = b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
    assert rejected_code("x.svg", svg, ["svg"]) == "svg_active_content"
