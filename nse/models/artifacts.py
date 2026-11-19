# Copyright (c) 2026 onyks
# Licensed under the MIT License.

"""Artifact hashing and atomic writes, shared by the reports and the CLI."""

from __future__ import annotations

import contextlib
import hashlib
import os
import tempfile
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class ArtifactEntry(BaseModel):
    """A file an experiment produced, identified by its content."""

    model_config = ConfigDict(frozen=True)

    path: str = Field(description="Absolute path at the time it was recorded.")
    sha256: str
    size: int


def artifact_entry(path: str | os.PathLike[str]) -> ArtifactEntry:
    """Hash *path* (streaming, any size) and describe it."""
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return ArtifactEntry(
        path=os.path.abspath(os.fspath(path)), sha256=digest.hexdigest(), size=size
    )


def write_text_atomic(
    path: str | os.PathLike[str], text: str, *, mode: int = 0o644
) -> ArtifactEntry:
    """Write *text* so that *path* is either absent, the old file, or complete.

    The data goes to a temporary file in the same directory, is flushed to disk,
    and then renamed over *path*. A reader never sees a half-written report,
    even when the writer is interrupted. The file gets *mode*. Returns the entry
    of the written file.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        # mkstemp creates 0600. Reports are meant to be collected, often by
        # another user than the root that ran NSE (a CI upload step), and hold
        # nothing but NSE's own records.
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise
    with contextlib.suppress(OSError):  # make the rename itself durable
        directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    return artifact_entry(target)
