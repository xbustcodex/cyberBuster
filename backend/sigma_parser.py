"""Sigma rule → hash IOC extractor.

Robust across common Sigma rule variants because it (a) parses the YAML doc
(multi-doc supported) to pull the rule title/level, then (b) sweeps the entire
document text for MD5 / SHA1 / SHA256 hex literals. That regex sweep survives
every dialect (`Hashes|contains: md5=...`, plain `sha256:` lists, prefixed
`0x...`, whatever) without maintaining a detection-schema whitelist.
"""
from __future__ import annotations

import re
from typing import Iterable

import yaml


_HASH_RE = re.compile(r"\b([A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b")


def _canonical_hash(value: str) -> str | None:
    v = value.strip().lower()
    if v.startswith("0x"):
        v = v[2:]
    if len(v) in (32, 40, 64) and re.fullmatch(r"[a-f0-9]+", v):
        return v
    return None


def parse_sigma(sigma_text: str) -> list[dict]:
    """Return a list of rule summaries with extracted hashes.

    Each entry: {title, id, level, hashes: [str], warnings: [str]}.
    """
    out: list[dict] = []
    if not sigma_text.strip():
        return out
    try:
        docs = list(yaml.safe_load_all(sigma_text))
    except yaml.YAMLError as e:
        return [{
            "title": "invalid yaml",
            "id": None, "level": None,
            "hashes": [], "warnings": [f"yaml parse error: {e}"],
        }]

    if not docs:
        # Fall through — still try regex sweep in case caller passed raw hash dumps.
        docs = [None]

    for doc in docs:
        title = None
        rule_id = None
        level = None
        source_text = sigma_text

        if isinstance(doc, dict):
            title = doc.get("title") or doc.get("name")
            rule_id = doc.get("id")
            level = doc.get("level")
            # Serialize this doc alone so hash extraction is per-rule
            try:
                source_text = yaml.safe_dump(doc, sort_keys=False)
            except Exception:
                source_text = str(doc)

        seen: set[str] = set()
        hashes: list[str] = []
        for m in _HASH_RE.finditer(source_text):
            h = _canonical_hash(m.group(1))
            if h and h not in seen:
                seen.add(h)
                hashes.append(h)

        warnings: list[str] = []
        if isinstance(doc, dict) and not doc.get("detection"):
            warnings.append("no `detection` block found")
        if not hashes:
            warnings.append("no MD5/SHA1/SHA256 hashes extracted")

        out.append({
            "title": title or "(untitled rule)",
            "id": rule_id,
            "level": level,
            "hashes": hashes,
            "warnings": warnings,
        })
    return out


def flatten_hashes(rules: Iterable[dict]) -> list[dict]:
    """Return [{hash, source_rule}] deduped across rules."""
    seen: set[str] = set()
    out: list[dict] = []
    for r in rules:
        for h in r.get("hashes", []):
            if h in seen:
                continue
            seen.add(h)
            out.append({"hash": h, "source_rule": r.get("title") or "(untitled)"})
    return out
