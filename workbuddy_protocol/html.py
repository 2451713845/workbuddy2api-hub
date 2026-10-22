from __future__ import annotations

from html.parser import HTMLParser
from typing import Optional


class _OneIdAnchorParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.href = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        if tag.lower() != "a" or self.href:
            return
        values = {key: value or "" for key, value in attrs}
        if values.get("data-idp") == "oneid":
            self.href = values.get("href", "")


def extract_oneid_login_url(html: str) -> str:
    parser = _OneIdAnchorParser()
    parser.feed(html)
    if not parser.href:
        raise RuntimeError("Keycloak page did not expose the OneID broker URL")
    return parser.href
