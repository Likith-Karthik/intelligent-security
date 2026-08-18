import hashlib
import re
from pathlib import Path
from uuid import UUID

from intelligent_security.domain import EvidenceArtifact


class ArtifactStore:
    """Append-only filesystem store for raw execution artifacts."""

    def __init__(self, root: str = "data/evidence") -> None:
        self.root = Path(root)

    def write_text(self, audit_id: UUID, evidence_id: UUID, kind: str, content: str, content_type: str) -> EvidenceArtifact:
        data = content.encode("utf-8")
        digest = hashlib.sha256(data).hexdigest()
        safe_kind = re.sub(r"[^a-z0-9_-]", "-", kind.lower())
        relative_path = Path(str(audit_id)) / str(evidence_id) / "{}-{}.txt".format(safe_kind, digest[:12])
        destination = self.root / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            with destination.open("xb") as artifact_file:
                artifact_file.write(data)
        except FileExistsError:
            # Content-addressed names make a repeated immutable write safe to reuse.
            if destination.read_bytes() != data:
                raise RuntimeError("Evidence artifact path collision detected.")
        return EvidenceArtifact(
            kind=kind,
            content_type=content_type,
            storage_uri="evidence://{}".format(relative_path.as_posix()),
            byte_size=len(data),
            sha256=digest,
        )

    def read_text(self, storage_uri: str, expected_sha256: str) -> str:
        prefix = "evidence://"
        if not storage_uri.startswith(prefix):
            raise RuntimeError("Unsupported evidence artifact URI.")
        relative_path = Path(storage_uri[len(prefix):])
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise RuntimeError("Evidence artifact URI escapes its store.")
        root = self.root.resolve()
        source = (root / relative_path).resolve()
        if root not in source.parents or not source.is_file():
            raise RuntimeError("Evidence artifact is unavailable.")
        data = source.read_bytes()
        if hashlib.sha256(data).hexdigest() != expected_sha256:
            raise RuntimeError("Evidence artifact checksum does not match its immutable record.")
        return data.decode("utf-8", errors="replace")
