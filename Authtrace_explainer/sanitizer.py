"""Small, conservative redaction helpers for AuthTrace report text."""
import re

_PATTERNS = (
    re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s,;]+"),
    re.compile(
        r"(?i)\b(password|passwd|api[_-]?key|access[_-]?token|"
        r"refresh[_-]?token|secret)\b(\s*[:=]\s*)(['\"]?)[^'\"\s,;]+"
    ),
    re.compile(r"(?i)(cookie\s*[:=]\s*)[^\r\n]+"),
)


def redact(text: str, limit: int = 2000) -> str:
    """Redact common credential formats and cap text length."""
    value = str(text)
    value = _PATTERNS[0].sub(r"\1[REDACTED]", value)
    value = _PATTERNS[1].sub(r"\1\2[REDACTED]", value)
    value = _PATTERNS[2].sub(r"\1[REDACTED]", value)
    return value[:limit]
