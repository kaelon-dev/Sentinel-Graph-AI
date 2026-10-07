"""Integrity and provenance tracking for SentinelGraph AI."""
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Union
from sentinelgraph.models import SourceFileMetadata
from sentinelgraph.version import __version__


def compute_sha256(content: Union[bytes, str, Path]) -> str:
    """Compute deterministic SHA-256 hex digest for bytes, string, or file path."""
    hasher = hashlib.sha256()
    if isinstance(content, Path) or (isinstance(content, str) and Path(content).is_file()):
        with open(content, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
    elif isinstance(content, str):
        hasher.update(content.encode("utf-8"))
    elif isinstance(content, bytes):
        hasher.update(content)
    else:
        hasher.update(str(content).encode("utf-8"))
    return hasher.hexdigest()


def generate_source_metadata(
    file_name: str,
    content_bytes: bytes,
    run_id: str
) -> SourceFileMetadata:
    """Create SourceFileMetadata with SHA-256 digest, size, and ingestion timestamp."""
    sha256 = hashlib.sha256(content_bytes).hexdigest()
    return SourceFileMetadata(
        file_name=file_name,
        size=len(content_bytes),
        sha256=sha256,
        ingestion_timestamp=datetime.now(timezone.utc),
        analysis_run_id=run_id,
        application_version=__version__
    )
