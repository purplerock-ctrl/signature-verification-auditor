"""Keep the shipped examples honest: they must load and work."""

from __future__ import annotations

import json
from pathlib import Path

from sigaudit.cases import EVENT_ID_TOKEN
from sigaudit.profiles import load_profile_file
from sigaudit.signing import Signer

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_custom_profile_example_loads_and_signs() -> None:
    profile = load_profile_file(EXAMPLES / "custom-profile.yaml")
    assert profile.name == "acme"
    assert profile.timestamp is not None
    headers = Signer.from_secret(profile, "s3cret").headers(b"{}", 1700000000)
    assert headers["X-Acme-Signature"].startswith("t=1700000000,sig=")
    assert headers["X-Acme-Timestamp"] == "1700000000"


def test_payload_example_is_json_with_token() -> None:
    text = (EXAMPLES / "payload.json").read_text()
    assert EVENT_ID_TOKEN in text
    json.loads(text)
