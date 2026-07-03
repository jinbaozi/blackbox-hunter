#!/usr/bin/env python3
"""Prompt-injection pattern detection for untrusted evidence.

The filter is intentionally conservative. It does not delete or rewrite evidence;
it marks suspicious content so later prompt construction can preserve it as data
inside an UNTRUSTED_EVIDENCE block.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import unicodedata
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable


DANGEROUS_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions?",
    r"disregard\s+(all\s+)?previous\s+instructions?",
    r"forget\s+(all\s+)?previous\s+instructions?",
    r"system\s+override",
    r"developer\s+mode",
    r"reveal\s+(the\s+)?(system\s+)?prompt",
    r"show\s+(the\s+)?(hidden\s+)?instructions?",
    r"do\s+not\s+report",
    r"delete\s+findings?",
    r"suppress\s+(this\s+)?finding",
    r"call\s+(the\s+)?tool",
    r"execute\s+(this\s+)?command",
    r"run\s+shell",
    r"exfiltrate",
    r"send\s+.*\s+to\s+https?://",
    r"curl\s+https?://",
    r"wget\s+https?://",
    r"<!--.*?(ignore|system|prompt|instruction).*?-->",
    r"display\s*:\s*none",
]

FUZZY_KEYWORDS = [
    "ignore",
    "bypass",
    "override",
    "reveal",
    "delete",
    "system",
    "prompt",
    "instruction",
]


@dataclass
class InjectionMatch:
    pattern: str
    offset: int
    severity: str
    excerpt: str
    source: str = "normalized"


@dataclass
class InjectionFilterResult:
    suspicious: bool
    matches: list[InjectionMatch] = field(default_factory=list)
    normalized_preview: str = ""
    policy: str = "wrapped_not_removed"

    def to_json(self) -> dict:
        return {
            "suspicious": self.suspicious,
            "matches": [asdict(item) for item in self.matches],
            "normalized_preview": self.normalized_preview,
            "policy": self.policy,
        }


def normalize_text(text: str) -> tuple[str, bool]:
    normalized = unicodedata.normalize("NFKC", text)
    stripped = "".join(ch for ch in normalized if unicodedata.category(ch) not in {"Cf", "Cc"} or ch in "\n\r\t")
    collapsed = re.sub(r"[ \t\r\f\v]+", " ", stripped)
    return collapsed, collapsed != text


def excerpt_around(text: str, start: int, end: int, radius: int = 48) -> str:
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    return text[left:right].replace("\n", "\\n")


def decode_base64_candidates(text: str, limit: int = 20) -> Iterable[tuple[str, str]]:
    candidates = re.findall(r"\b[A-Za-z0-9+/]{16,}={0,2}\b", text)
    for item in candidates[:limit]:
        try:
            raw = base64.b64decode(item, validate=True)
        except (binascii.Error, ValueError):
            continue
        if 4 <= len(raw) <= 4096:
            decoded = raw.decode("utf-8", errors="ignore")
            if decoded:
                yield "base64", decoded


def decode_hex_candidates(text: str, limit: int = 20) -> Iterable[tuple[str, str]]:
    candidates = re.findall(r"\b(?:0x)?[0-9a-fA-F]{24,}\b", text)
    for item in candidates[:limit]:
        value = item[2:] if item.lower().startswith("0x") else item
        if len(value) % 2 != 0:
            continue
        try:
            raw = bytes.fromhex(value)
        except ValueError:
            continue
        if 4 <= len(raw) <= 4096:
            decoded = raw.decode("utf-8", errors="ignore")
            if decoded:
                yield "hex", decoded


def is_typoglycemia_variant(word: str, target: str) -> bool:
    if len(word) != len(target) or len(word) < 4:
        return False
    return word[0] == target[0] and word[-1] == target[-1] and sorted(word[1:-1]) == sorted(target[1:-1]) and word != target


def scan_text(text: str, *, source: str) -> list[InjectionMatch]:
    matches: list[InjectionMatch] = []
    for pattern in DANGEROUS_PATTERNS:
        for match in re.finditer(pattern, text, flags=re.IGNORECASE | re.DOTALL):
            matches.append(
                InjectionMatch(
                    pattern=pattern,
                    offset=match.start(),
                    severity="high",
                    excerpt=excerpt_around(text, match.start(), match.end()),
                    source=source,
                )
            )

    lowered = text.lower()
    for word_match in re.finditer(r"\b[a-zA-Z]{4,}\b", lowered):
        word = word_match.group(0)
        for keyword in FUZZY_KEYWORDS:
            if is_typoglycemia_variant(word, keyword):
                matches.append(
                    InjectionMatch(
                        pattern=f"typoglycemia:{keyword}",
                        offset=word_match.start(),
                        severity="medium",
                        excerpt=excerpt_around(text, word_match.start(), word_match.end()),
                        source=source,
                    )
                )
    return matches


def detect_injection(text: str, *, preview_chars: int = 500) -> InjectionFilterResult:
    normalized, changed = normalize_text(text)
    matches = scan_text(normalized, source="normalized")

    if changed:
        matches.append(
            InjectionMatch(
                pattern="unicode_control_or_normalization",
                offset=0,
                severity="low",
                excerpt="unicode control characters or normalization changes detected",
                source="normalizer",
            )
        )

    for source, decoded in list(decode_base64_candidates(normalized)) + list(decode_hex_candidates(normalized)):
        decoded_normalized, _ = normalize_text(decoded)
        decoded_matches = scan_text(decoded_normalized, source=source)
        matches.extend(decoded_matches)

    preview = normalized[:preview_chars]
    return InjectionFilterResult(
        suspicious=bool(matches),
        matches=matches,
        normalized_preview=preview,
    )


def detect_file(path: Path) -> InjectionFilterResult:
    return detect_injection(path.read_text(encoding="utf-8", errors="replace"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detect prompt-injection-like content in untrusted evidence")
    parser.add_argument("path", help="Path to text file to scan")
    parser.add_argument("--output", default="", help="Optional JSON output path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = detect_file(Path(args.path))
    payload = json.dumps(result.to_json(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    return 1 if result.suspicious else 0


if __name__ == "__main__":
    raise SystemExit(main())
