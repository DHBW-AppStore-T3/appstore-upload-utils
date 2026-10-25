"""Verify that hostile_archives.py generates valid (non-empty) archives for all cases."""
from appstore_upload_utils.hostile_archives import HOSTILE_ARCHIVES


def test_hostile_archives_is_not_empty():
    assert len(HOSTILE_ARCHIVES) >= 20


def test_each_hostile_archive_has_a_label_and_bytes():
    for label, data in HOSTILE_ARCHIVES:
        assert isinstance(label, str) and label
        assert isinstance(data, bytes) and data
