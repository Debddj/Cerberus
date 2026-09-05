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
    def redact_value(cls, value: Any, parent_key: str = "") -> tuple[Any, list[str]]:
        """Recursively redact a value of any type, returning (redacted_value, fields_modified)."""
        fields_modified: list[str] = []

        if isinstance(value, str):
            redacted, was_modified = cls.redact_text(value)
            if was_modified:
                fields_modified.append(parent_key or "<root>")
            return redacted, fields_modified

        if isinstance(value, dict):
            redacted_dict, dict_fields = cls.redact_dict(value)
            if parent_key and dict_fields:
                fields_modified.extend(f"{parent_key}.{f}" for f in dict_fields)
            else:
                fields_modified.extend(dict_fields)
            return redacted_dict, fields_modified

        if isinstance(value, list):
            redacted_list, list_fields = cls.redact_list(value, parent_key)
            fields_modified.extend(list_fields)
            return redacted_list, fields_modified

        return value, fields_modified

    @classmethod
    def redact_list(cls, data: list[Any], parent_key: str = "") -> tuple[list[Any], list[str]]:
        """Recursively redact list elements."""
        redacted: list[Any] = []
        fields_modified: list[str] = []
        for idx, item in enumerate(data):
            item_key = f"{parent_key}[{idx}]" if parent_key else f"[{idx}]"
            redacted_item, item_fields = cls.redact_value(item, item_key)
            redacted.append(redacted_item)
            fields_modified.extend(item_fields)
        return redacted, fields_modified

    @classmethod
    def redact_dict(cls, data: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
        redacted: dict[str, Any] = {}
        fields_redacted: list[str] = []
        for k, v in data.items():
            key_is_sensitive = any(kw in k.lower() for kw in SENSITIVE_KEY_KEYWORDS)
            if key_is_sensitive and isinstance(v, str):
                redacted[k] = "[REDACTED_SECRET]"
                fields_redacted.append(k)
            elif key_is_sensitive and isinstance(v, list):
                # Sensitive key with list value — redact all elements
                red_elements = []
                for idx, el in enumerate(v):
                    item_key = f"{k}[{idx}]"
                    if isinstance(el, str):
                        red_elements.append("[REDACTED_SECRET]")
                        fields_redacted.append(item_key)
                    else:
                        red_val, ch_fields = cls.redact_value(el, item_key)
                        red_elements.append(red_val)
                        fields_redacted.extend(ch_fields)
                redacted[k] = red_elements
            else:
                redacted_val, child_fields = cls.redact_value(v, k)
                redacted[k] = redacted_val
                fields_redacted.extend(child_fields)
        return redacted, fields_redacted
