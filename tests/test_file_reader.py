import os
from pathlib import Path

import pytest

from github_security_agent.file_reader import read_repository_file


def test_exact_limit_and_overflow(tmp_path: Path):
    (tmp_path / "file").write_bytes(b"1234")
    assert read_repository_file(tmp_path, Path("file"), 4) == b"1234"
    with pytest.raises(OSError):
        read_repository_file(tmp_path, Path("file"), 3)


def test_rejects_leaf_and_ancestor_symlinks(tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "file").write_bytes(b"secret")
    root = tmp_path / "root"
    root.mkdir()
    (root / "leaf").symlink_to(outside / "file")
    (root / "directory").symlink_to(outside, target_is_directory=True)
    for relative in (Path("leaf"), Path("directory/file")):
        with pytest.raises(OSError):
            read_repository_file(root, relative, 100)


def test_rejects_nonregular_file_without_blocking(tmp_path: Path):
    os.mkfifo(tmp_path / "fifo")
    with pytest.raises(OSError):
        read_repository_file(tmp_path, Path("fifo"), 100)


def test_unsupported_platform_fails_closed(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(os, "supports_dir_fd", set())
    with pytest.raises(OSError, match="unavailable"):
        read_repository_file(tmp_path, Path("file"), 100)


def test_parent_replaced_before_open_is_rejected(tmp_path: Path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    (root / "parent").mkdir()
    (root / "parent" / "file").write_bytes(b"safe")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "file").write_bytes(b"external secret")
    original = os.open

    def replace_parent(path, flags, *, dir_fd=None):
        if path == "parent":
            (root / "parent").rename(root / "old-parent")
            (root / "parent").symlink_to(outside, target_is_directory=True)
        return original(path, flags, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", replace_parent)
    monkeypatch.setattr(os, "supports_dir_fd", {replace_parent})
    with pytest.raises(OSError):
        read_repository_file(root, Path("parent/file"), 100)


def test_root_ancestor_swap_is_rejected(tmp_path: Path, monkeypatch):
    holder = tmp_path / "holder"
    root = holder / "root"
    root.mkdir(parents=True)
    (root / "file").write_bytes(b"safe")
    outside = tmp_path / "outside"
    (outside / "root").mkdir(parents=True)
    (outside / "root/file").write_bytes(b"external")
    original = os.open

    def swap(path, flags, *, dir_fd=None):
        if path == "holder":
            holder.rename(tmp_path / "old-holder")
            holder.symlink_to(outside, target_is_directory=True)
        return original(path, flags, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", swap)
    monkeypatch.setattr(os, "supports_dir_fd", {swap})
    with pytest.raises(OSError):
        read_repository_file(root, Path("file"), 100)


def test_pinned_root_survives_parent_replacement(tmp_path: Path):
    from github_security_agent.file_reader import open_repository_root

    holder = tmp_path / "holder"
    root = holder / "root"
    root.mkdir(parents=True)
    (root / "file").write_bytes(b"safe")
    outside = tmp_path / "outside"
    (outside / "root").mkdir(parents=True)
    (outside / "root/file").write_bytes(b"external")
    with open_repository_root(root) as descriptor:
        holder.rename(tmp_path / "old-holder")
        holder.symlink_to(outside, target_is_directory=True)
        assert read_repository_file(descriptor, Path("file"), 100) == b"safe"


def test_root_ancestor_already_replaced_is_rejected(tmp_path: Path):
    configured = tmp_path / "holder/root"
    outside = tmp_path / "outside"
    (outside / "root").mkdir(parents=True)
    (outside / "root/file").write_bytes(b"external")
    (tmp_path / "holder").symlink_to(outside, target_is_directory=True)
    with pytest.raises(OSError):
        read_repository_file(configured, Path("file"), 100)
