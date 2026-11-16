from __future__ import annotations

import pytest

from sigaudit.classify import (
    Classifier,
    MatcherError,
    Outcome,
    ResponseMatcher,
    parse_status_spec,
)


def test_parse_status_spec() -> None:
    assert parse_status_spec("2xx") == frozenset(range(200, 300))
    assert parse_status_spec("200, 202") == {200, 202}
    assert parse_status_spec("200-204,409") == {200, 201, 202, 203, 204, 409}
    assert parse_status_spec("4XX") == frozenset(range(400, 500))


@pytest.mark.parametrize("spec", ["", "abc", "20", "6xx", "204-200", "999", "2xx,", ","])
def test_parse_status_spec_rejects_garbage(spec: str) -> None:
    if spec == "2xx,":
        assert parse_status_spec(spec) == frozenset(range(200, 300))  # trailing comma is fine
        return
    with pytest.raises(MatcherError):
        parse_status_spec(spec)


def test_default_classifier() -> None:
    c = Classifier()
    assert c.classify(200, "") is Outcome.ACCEPTED
    assert c.classify(204, "") is Outcome.ACCEPTED
    assert c.classify(302, "") is Outcome.REJECTED
    assert c.classify(401, "") is Outcome.REJECTED
    assert c.classify(500, "") is Outcome.REJECTED
    assert c.describe() == {"accepted_when": "status in 2xx", "rejected_when": "anything else"}


def test_body_matchers_for_apps_that_always_return_200() -> None:
    c = Classifier(
        accept=ResponseMatcher.build("2xx", '"received": true'),
        reject=ResponseMatcher.build(body_contains="invalid signature"),
    )
    assert c.classify(200, '{"received": true}') is Outcome.ACCEPTED
    assert c.classify(200, '{"error": "invalid signature"}') is Outcome.REJECTED
    assert c.classify(200, "something else") is Outcome.UNCLEAR
    assert c.classify(500, '"received": true, "invalid signature"') is Outcome.REJECTED


def test_both_matching_is_unclear() -> None:
    c = Classifier(
        accept=ResponseMatcher.build("2xx"), reject=ResponseMatcher.build(body_contains="error")
    )
    assert c.classify(200, "error") is Outcome.UNCLEAR


def test_matcher_requires_a_condition() -> None:
    with pytest.raises(MatcherError):
        ResponseMatcher.build()
    with pytest.raises(MatcherError):
        ResponseMatcher.build(body_contains="")


def test_describe() -> None:
    m = ResponseMatcher.build("200", "ok")
    assert m.describe() == "status in 200 and body contains 'ok'"


def test_reject_rule_alone_takes_precedence_over_default_2xx() -> None:
    c = Classifier(reject=ResponseMatcher.build(body_contains="invalid signature"))
    assert c.classify(200, '{"error": "invalid signature"}') is Outcome.REJECTED
    assert c.classify(200, '{"received": true}') is Outcome.ACCEPTED
    assert c.classify(401, "unauthorized") is Outcome.REJECTED
    assert "not rejected" in c.describe()["accepted_when"]


def test_accept_rule_alone() -> None:
    c = Classifier(accept=ResponseMatcher.build("202"))
    assert c.classify(202, "") is Outcome.ACCEPTED
    assert c.classify(200, "") is Outcome.REJECTED
