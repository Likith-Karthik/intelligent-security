"""Citation-constrained AI normalization for bounded recon evidence."""

import hashlib
import json
import re
from urllib.parse import urlparse
from uuid import UUID

from intelligent_security.domain import Audit, ReconEvidenceChunk, ReconObservation, ReconScopeStatus
from intelligent_security.evidence.artifact_store import ArtifactStore
from intelligent_security.intelligence.service import IntelligenceService


class ReconNormalizationError(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.code, self.message = code, message
        super().__init__(message)


class ReconNormalizer:
    """Retains raw evidence and accepts model facts only when cited evidence supports them."""

    chunk_size, max_chunks = 6000, 100
    secret_pattern = re.compile(r"(?i)(authorization\s*[:=]\s*\S+|(?:api[_-]?key|token|password|secret)\s*[:=]\s*\S+)")

    def __init__(self, intelligence: IntelligenceService) -> None:
        self.intelligence = intelligence

    def normalize(self, audit: Audit, evidence_id: UUID, store: ArtifactStore) -> tuple:
        evidence = next((item for item in audit.raw_evidence if item.evidence_id == evidence_id), None)
        if evidence is None:
            raise ReconNormalizationError("unknown_evidence", "Evidence does not belong to this audit.")
        stdout = next((item for item in evidence.artifacts if item.kind == "stdout"), None)
        if stdout is None:
            raise ReconNormalizationError("missing_stdout", "Recon evidence has no stdout artifact.")
        try:
            raw = store.read_text(stdout.storage_uri, stdout.sha256)
        except RuntimeError as error:
            raise ReconNormalizationError("evidence_unavailable", str(error))
        chunks = self._chunks(evidence_id, stdout.kind, stdout.sha256, raw)
        deterministic = self._deterministic(audit, evidence_id, evidence.completed_at, raw, chunks)
        try:
            generated, provenance = self.intelligence.generate("recon_normalization", self._prompt(), {
                "evidence_id": str(evidence_id),
                "chunks": [item.model_dump(mode="json") for item in chunks],
                "deterministic_observations": [item.model_dump(mode="json") for item in deterministic],
            })
        except Exception as error:
            raise ReconNormalizationError("model_normalization_failed", "Recon normalization model failed: {}".format(error))
        return self._dedupe(deterministic + self._model_observations(audit, evidence_id, evidence.completed_at, generated, chunks)), chunks, provenance

    @staticmethod
    def _prompt() -> str:
        return (
            "Return JSON only: {\"observations\":[...]}. Each observation has observation_type "
            "(asset, service, technology, endpoint, interface), value, parent_asset, confidence, source_chunk_ids, "
            "normalized_summary, optional semantic_cluster_id. Cite chunks for every fact. Extract only explicit evidence; "
            "never invent vulnerabilities, targets, credentials, or unsupported facts."
        )

    def _chunks(self, evidence_id, kind, artifact_sha, raw):
        text = self.secret_pattern.sub("[REDACTED]", raw)
        result = []
        for start in range(0, min(len(text), self.chunk_size * self.max_chunks), self.chunk_size):
            excerpt = text[start : start + self.chunk_size]
            digest = hashlib.sha256(excerpt.encode()).hexdigest()
            result.append(ReconEvidenceChunk(chunk_id="chunk-{}".format(digest[:16]), evidence_id=evidence_id,
                artifact_kind=kind, sha256=digest, source_artifact_sha256=artifact_sha,
                start_offset=start, end_offset=start + len(excerpt), text=excerpt))
        return result

    def _deterministic(self, audit, evidence_id, observed_at, raw, chunks):
        result, offset = [], 0
        for line in raw.splitlines(keepends=True)[:1000]:
            start, offset = offset, offset + len(line)
            try: record = json.loads(line)
            except ValueError: continue
            if not isinstance(record, dict): continue
            host, url = self._host(record.get("host")), self._url(record.get("url"))
            if not host and not url: continue
            parent, status = host or urlparse(url).hostname, self._scope(audit, host or urlparse(url).hostname)
            chunk_ids = [item.chunk_id for item in chunks if item.start_offset <= start < item.end_offset]
            if host: result.append(self._obs("asset", host, parent, evidence_id, observed_at, status, chunk_ids))
            if url:
                result += [self._obs("interface", url, parent, evidence_id, observed_at, status, chunk_ids),
                           self._obs("endpoint", urlparse(url).path or "/", parent, evidence_id, observed_at, status, chunk_ids)]
            if parent and record.get("scheme") and record.get("port"):
                result.append(self._obs("service", "{}:{}".format(record["scheme"], record["port"]), parent, evidence_id, observed_at, status, chunk_ids))
            server = self._header(record.get("response", ""), "server")
            if server: result.append(self._obs("technology", server, parent, evidence_id, observed_at, status, chunk_ids))
        return self._dedupe(result)

    def _model_observations(self, audit, evidence_id, observed_at, generated, chunks):
        if not isinstance(generated, dict) or not isinstance(generated.get("observations"), list):
            raise ReconNormalizationError("invalid_model_output", "Recon normalization output must contain observations.")
        chunk_map, result = {item.chunk_id: item for item in chunks}, []
        for proposal in generated["observations"][:1000]:
            if not isinstance(proposal, dict): continue
            kind, value, cited = proposal.get("observation_type"), proposal.get("value"), proposal.get("source_chunk_ids")
            if kind not in {"asset", "service", "technology", "endpoint", "interface"} or not isinstance(value, str): continue
            if not isinstance(cited, list) or not cited or any(item not in chunk_map for item in cited): continue
            if value.lower() not in "\n".join(chunk_map[item].text for item in cited).lower(): continue
            confidence = proposal.get("confidence", 0)
            if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1: continue
            canonical = self._value(kind, value)
            if not canonical: continue
            parent = self._host(proposal.get("parent_asset"))
            result.append(ReconObservation(observation_type=kind, value=canonical, parent_asset=parent, source_evidence_id=evidence_id,
                confidence=float(confidence), first_observed_at=observed_at, last_observed_at=observed_at, scope_status=self._scope(audit, parent),
                source_chunk_ids=cited, normalized_summary=str(proposal.get("normalized_summary", ""))[:2000] or None,
                semantic_cluster_id=str(proposal.get("semantic_cluster_id", ""))[:200] or None, model_assisted=True))
        return result

    @staticmethod
    def _obs(kind, value, parent, evidence_id, seen_at, scope, chunk_ids):
        return ReconObservation(observation_type=kind, value=value, parent_asset=parent, source_evidence_id=evidence_id,
            confidence=0.9, first_observed_at=seen_at, last_observed_at=seen_at, scope_status=scope, source_chunk_ids=chunk_ids)

    @staticmethod
    def _dedupe(items):
        result = {}
        for item in items:
            key = (item.observation_type, item.value, item.parent_asset, item.source_evidence_id)
            if key not in result or item.confidence > result[key].confidence: result[key] = item
        return list(result.values())

    @staticmethod
    def _host(value): return value.lower().rstrip(".") if isinstance(value, str) and value.strip() else None

    def _value(self, kind, value):
        if kind == "asset": return self._host(value)
        if kind == "interface": return self._url(value)
        return value.strip()[:2048] or None

    @staticmethod
    def _url(value):
        if not isinstance(value, str): return None
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname: return None
        return "{}://{}{}".format(parsed.scheme.lower(), parsed.hostname.lower().rstrip("."), parsed.path.rstrip("/") or "/")

    @staticmethod
    def _header(response, name):
        for line in response.split("\r\n") if isinstance(response, str) else []:
            if line.lower().startswith(name.lower() + ":"): return line.split(":", 1)[1].strip()[:200] or None
        return None

    @staticmethod
    def _scope(audit, host):
        return ReconScopeStatus.IN_SCOPE if host in set(audit.scope_policy.network_allowlist if audit.scope_policy else []) else ReconScopeStatus.OUT_OF_SCOPE
