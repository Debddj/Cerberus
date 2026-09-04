from collections.abc import Iterable
from typing import ClassVar


class LethalTrifectaDetector:
    """
    Detects when an agent simultaneously possesses:
    1. Private data access
    2. Untrusted content exposure
    3. External egress capability
    """

    PRIVATE_DATA_KEYWORDS: ClassVar[set[str]] = {
        "read",
        "query",
        "select",
        "fetch_db",
        "get_secret",
        "file_read",
        "credentials",
    }
    UNTRUSTED_CONTENT_KEYWORDS: ClassVar[set[str]] = {
        "inbox",
        "scrape",
        "fetch_url",
        "search_web",
        "parse_issue",
        "receive_email",
    }
    EXTERNAL_EGRESS_KEYWORDS: ClassVar[set[str]] = {
        "http_post",
        "send_email",
        "webhook",
        "upload",
        "publish",
        "post_message",
    }

    @classmethod
    def classify_tool(cls, tool_name: str) -> set[str]:
        name_lower = tool_name.lower()
        capabilities = set()

        if any(k in name_lower for k in cls.PRIVATE_DATA_KEYWORDS):
            capabilities.add("private_data")
        if any(k in name_lower for k in cls.UNTRUSTED_CONTENT_KEYWORDS):
            capabilities.add("untrusted_content")
        if any(k in name_lower for k in cls.EXTERNAL_EGRESS_KEYWORDS):
            capabilities.add("external_egress")

        return capabilities

    @classmethod
    def check_session_tools(cls, tool_names: Iterable[str]) -> tuple[bool, dict[str, list[str]]]:
        breakdown: dict[str, list[str]] = {
            "private_data": [],
            "untrusted_content": [],
            "external_egress": [],
        }

        for t in tool_names:
            caps = cls.classify_tool(t)
            for c in caps:
                breakdown[c].append(t)

        is_trifecta = (
            len(breakdown["private_data"]) > 0
            and len(breakdown["untrusted_content"]) > 0
            and len(breakdown["external_egress"]) > 0
        )
        return is_trifecta, breakdown
