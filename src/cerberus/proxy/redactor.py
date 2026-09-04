import re
from typing import Any

SECRET_PATTERNS = [
    r"(?i)(api[_-]?key|token|secret|password|passwd|auth)\s*[=:]\s*([\'\"\w\-]{8,})",
    r"(?i)bearer\s+([A-Za-z0-9_\-\.~+/=]{16,})",
    r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----[\s\S]+?-----END\s+(RSA\s+)?PRIVATE\s+KEY-----",
    r"ghp_[a-zA-Z0-9]{36}",
    r"sk-[a-zA-Z0-9]{48}",
    r"AIza[0-9A-Za-z_-]{35}",
    r"AKIA[0-9A-Z]{16}",
]

COMPILED_PATTERNS = [re.compile(p) for p in SECRET_PATTERNS]

SENSITIVE_KEY_KEYWORDS = ["api_key", "apikey", "token", "secret", "password", "passwd", "auth"]


class SecretRedactor:
    """Redacts credentials, tokens, and PII from parameters and payloads before persistence."""

    @classmethod
    def redact_text(cls, text: str) -> tuple[str, bool]:
        if not text:
            return text, False
        modified = False
        res = text
        for pat in COMPILED_PATTERNS:
            if pat.search(res):
                res = pat.sub("[REDACTED_SECRET]", res)
                modified = True
        return res, modified

    @classmethod
    def redact_dict(cls, data: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
        redacted = {}
        fields_redacted = []
        for k, v in data.items():
            key_is_sensitive = any(kw in k.lower() for kw in SENSITIVE_KEY_KEYWORDS)
            if key_is_sensitive and isinstance(v, str):
                redacted[k] = "[REDACTED_SECRET]"
                fields_redacted.append(k)
            elif isinstance(v, str):
                v_red, mod = cls.redact_text(v)
                redacted[k] = v_red
                if mod:
                    fields_redacted.append(k)
            elif isinstance(v, dict):
                v_red, child_mods = cls.redact_dict(v)
                redacted[k] = v_red
                if child_mods:
                    fields_redacted.extend([f"{k}.{c}" for c in child_mods])
            else:
                redacted[k] = v
        return redacted, fields_redacted
