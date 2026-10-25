"""Tests for appstore_upload_utils.upload_formats."""

from __future__ import annotations

import struct
import zlib

import pytest

from appstore_upload_utils.upload_formats import FormatRejected, inspect_pdf, inspect_png, inspect_jpeg

try:
    from tests.upload_samples import png, jpeg
except ImportError:
    from upload_samples import png, jpeg

PNG = png()
JPEG = jpeg()
PDF = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF\n"


def test_valid_png_passes():
    inspect_png(PNG)


def test_valid_jpeg_passes():
    inspect_jpeg(JPEG)


def test_valid_pdf_passes():
    inspect_pdf(PDF)


@pytest.mark.parametrize("extra,code", [
    (b"/JavaScript (alert(1)) endobj", "pdf_active_content"),
])
def test_pdf_with_active_content_is_rejected(extra, code):
    bad = b"%PDF-1.4\n" + extra + b"\n%%EOF\n"
    with pytest.raises(FormatRejected) as exc:
        inspect_pdf(bad)
    assert exc.value.code == code


def test_png_that_truncates_is_rejected():
    with pytest.raises(FormatRejected):
        inspect_png(PNG[:-20])


def test_image_with_too_many_pixels_is_rejected():
    def chunk(name, data):
        c = struct.pack(">I", len(data)) + name + data
        return c + struct.pack(">I", zlib.crc32(name + data) & 0xFFFFFFFF)

    width = height = 20000  # 4e8 > 1e8 limit
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    row = b"\x00" + b"\xff" * (width * 3)
    idat_data = zlib.compress(row * min(height, 5))  # enough for the header
    iend_data = b""
    png_data = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr_data)
        + chunk(b"IDAT", idat_data)
        + chunk(b"IEND", iend_data)
    )
    with pytest.raises(FormatRejected) as exc:
        inspect_png(png_data)
    assert exc.value.code == "image_too_large"
