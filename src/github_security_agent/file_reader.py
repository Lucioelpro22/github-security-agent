"""Bounded reads anchored to a directory, with symlinks rejected at every component."""

from contextlib import contextmanager
from collections.abc import Iterator

import os
import stat
from pathlib import Path


@contextmanager
def open_repository_root(root: Path) -> Iterator[int]:
    """Pin a canonical root while rejecting symlinks in its absolute path."""
    if os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW"):
        raise OSError("safe repository file reads are unavailable on this platform")
    canonical = root.absolute()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(canonical.anchor, flags)
    try:
        for component in canonical.parts[1:]:
            next_fd = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_fd
        yield descriptor
    finally:
        os.close(descriptor)


def read_repository_file(root: Path | int, relative: Path, limit: int) -> bytes:
    """Read a bounded regular file beneath an already pinned root descriptor."""
    if isinstance(root, Path):
        with open_repository_root(root) as descriptor:
            return read_repository_file(descriptor, relative, limit)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts or limit < 0:
        raise OSError("invalid repository file read")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory_fd = os.dup(root)
    try:
        for component in relative.parts[:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(
            relative.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory_fd,
        )
        with os.fdopen(file_fd, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
                raise OSError("repository file is not regular or exceeds the read limit")
            data = stream.read(limit + 1)
            if len(data) > limit:
                raise OSError("repository file exceeds the read limit")
            return data
    finally:
        os.close(directory_fd)
