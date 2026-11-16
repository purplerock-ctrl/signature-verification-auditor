from __future__ import annotations

import io

import pytest

from sigaudit.authorization import (
    REMINDER,
    AuthorizationRefused,
    require_authorization,
    target_host,
)

URL = "https://Staging.Example.test:8443/hooks/stripe"


def test_reminder_is_always_printed_even_with_flag() -> None:
    out = io.StringIO()
    record = require_authorization(URL, flag=True, scope_note="own staging", is_tty=False, out=out)
    assert REMINDER in out.getvalue()
    assert record.method == "flag"
    assert record.target_host == "staging.example.test"
    assert "own staging" in record.statement()


def test_non_interactive_without_flag_refuses() -> None:
    def fail(_prompt: str) -> str:
        raise AssertionError("must not prompt without a TTY")

    with pytest.raises(AuthorizationRefused, match="--i-am-authorized"):
        require_authorization(
            URL, flag=False, scope_note=None, is_tty=False, input_fn=fail, out=io.StringIO()
        )


def test_interactive_requires_typing_the_host() -> None:
    record = require_authorization(
        URL,
        flag=False,
        scope_note=None,
        is_tty=True,
        input_fn=lambda _p: "  STAGING.example.test ",
        out=io.StringIO(),
    )
    assert record.method == "interactive"


@pytest.mark.parametrize("answer", ["y", "yes", "", "production.example.test"])
def test_interactive_wrong_answer_refuses(answer: str) -> None:
    with pytest.raises(AuthorizationRefused):
        require_authorization(
            URL,
            flag=False,
            scope_note=None,
            is_tty=True,
            input_fn=lambda _p: answer,
            out=io.StringIO(),
        )


def test_eof_at_prompt_refuses() -> None:
    def eof(_prompt: str) -> str:
        raise EOFError

    with pytest.raises(AuthorizationRefused):
        require_authorization(
            URL, flag=False, scope_note=None, is_tty=True, input_fn=eof, out=io.StringIO()
        )


def test_target_host() -> None:
    assert target_host("http://127.0.0.1:8000/x") == "127.0.0.1"
    with pytest.raises(ValueError, match="host"):
        target_host("not a url")
