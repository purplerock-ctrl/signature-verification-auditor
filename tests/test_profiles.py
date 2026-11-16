from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sigaudit.profiles import (
    Encoding,
    ProfileError,
    builtin_profile_names,
    load_builtin_profile,
    load_profile_file,
    profile_from_dict,
    resolve_profile,
)


def base(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "name": "test",
        "description": "test profile",
        "algorithm": "sha256",
        "signed_payload": "{body}",
        "signature_header": "X-Sig",
        "signature_format": "{signature}",
    }
    data.update(overrides)
    return data


def test_all_builtins_load() -> None:
    names = builtin_profile_names()
    assert {"generic-hmac-sha256", "stripe", "github", "shopify", "slack"} <= set(names)
    for name in names:
        assert load_builtin_profile(name).name == name


def test_minimal_profile_defaults() -> None:
    p = profile_from_dict(base())
    assert p.signature_encoding is Encoding.HEX
    assert p.timestamp is None
    assert not p.uses_timestamp
    assert p.content_type == "application/json"


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"signed_payload": "{timestamp}"}, "exactly once"),
        ({"signed_payload": "{body}{body}"}, "exactly once"),
        ({"signed_payload": "{body}.{nonce}"}, "unknown placeholder"),
        ({"signature_format": "sha256="}, "exactly once"),
        ({"signature_format": "{signature}{kid}"}, "unknown placeholder"),
        ({"signed_payload": "{timestamp}.{body}"}, "no 'timestamp' section"),
        ({"algorithm": "md5"}, "must be one of"),
        ({"signature_encoding": "base32"}, "must be one of"),
        ({"signature_header": "Bad Header"}, "not a valid HTTP header"),
        ({"name": "Has Spaces"}, "name must be"),
        ({"description": "  "}, "description"),
        ({"signed_paylaod": "{body}"}, "unknown key"),
        ({"timestamp": {"tolerance_seconds": 300}}, "unsigned timestamp"),
        (
            {"signed_payload": "{timestamp}.{body}", "timestamp": {"tolerance_seconds": 300}},
            "never sent",
        ),
        (
            {
                "signed_payload": "{timestamp}.{body}",
                "timestamp": {"tolerance_seconds": 0, "header": "X-Ts"},
            },
            "positive",
        ),
        (
            {
                "signed_payload": "{timestamp}.{body}",
                "timestamp": {"header": "x-sig"},
            },
            "must differ",
        ),
        ({"timestamp": {"tolerance": 5}}, "unknown key"),
        ({"extra_headers": {"X-A": 1}}, "extra_headers"),
    ],
)
def test_validation_errors(overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(ProfileError, match=message):
        profile_from_dict(base(**overrides))


def test_missing_required_key() -> None:
    data = base()
    del data["signature_header"]
    with pytest.raises(ProfileError, match="missing required"):
        profile_from_dict(data)


def test_not_a_mapping() -> None:
    with pytest.raises(ProfileError, match="mapping"):
        profile_from_dict(["nope"])


def test_load_yaml_and_json_files(tmp_path: Path) -> None:
    data = base(
        name="custom",
        signed_payload="{timestamp}:{body}",
        timestamp={"tolerance_seconds": 60, "header": "X-Ts"},
        extra_headers={"X-Event": "test"},
    )
    yaml_file = tmp_path / "custom.yaml"
    yaml_file.write_text(
        "name: custom\n"
        "description: test profile\n"
        "algorithm: SHA256\n"
        'signed_payload: "{timestamp}:{body}"\n'
        "signature_header: X-Sig\n"
        'signature_format: "{signature}"\n'
        "timestamp:\n  tolerance_seconds: 60\n  header: X-Ts\n"
        "extra_headers:\n  X-Event: test\n"
    )
    json_file = tmp_path / "custom.json"
    json_file.write_text(json.dumps(data))

    from_yaml = load_profile_file(yaml_file)
    from_json = load_profile_file(json_file)
    assert from_yaml == from_json
    assert from_yaml.timestamp is not None
    assert from_yaml.timestamp.header == "X-Ts"
    assert dict(from_yaml.extra_headers) == {"X-Event": "test"}
    assert resolve_profile(str(yaml_file)) == from_yaml


def test_errors_name_the_source_file(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("name: bad\n")
    with pytest.raises(ProfileError, match=r"bad\.yaml"):
        load_profile_file(bad)


def test_invalid_yaml(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("name: [unclosed\n")
    with pytest.raises(ProfileError, match="not valid"):
        load_profile_file(bad)


def test_unsafe_yaml_tags_are_refused(tmp_path: Path) -> None:
    # safe_load must refuse to construct Python objects from tags.
    evil = tmp_path / "evil.yaml"
    evil.write_text("!!python/object/apply:os.system ['echo pwned']\n")
    with pytest.raises(ProfileError):
        load_profile_file(evil)


def test_unknown_builtin() -> None:
    with pytest.raises(ProfileError, match="unknown built-in profile"):
        resolve_profile("does-not-exist")


def test_missing_file() -> None:
    with pytest.raises(ProfileError, match="cannot read"):
        resolve_profile("nope/missing.yaml")
