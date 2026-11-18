# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `examples/stripe-receiver/`: a case study with a Flask receiver that has a
  correct endpoint (Stripe's official library) and a naive one with two
  common mistakes, plus a step-by-step guide to auditing and fixing it. A
  test runs the audit in CI and confirms Stripe's library accepts sigaudit's
  signatures.
- `examples` install extra (`pip install -e ".[examples]"`).

## [0.1.0] - 2026-11-16

First public release.

### Added

- `sigaudit run`: audits a webhook endpoint's HMAC signature verification with
  eight cases: a valid control, missing / empty / malformed signature, wrong
  secret, tampered body, replayed (old) timestamp, and wrong hash algorithm.
- An authorization gate on every run: `--i-am-authorized`, or typing the
  target hostname interactively. It refuses when non-interactive. Every run
  prints a legal reminder, and reports record how authorization was confirmed.
- Rate limiting: one request at a time, 1/s by default, hard ceiling of 5/s.
- Provider profiles in YAML/JSON with strict validation, and built-in profiles
  for generic HMAC-SHA256, Stripe-, GitHub-, Shopify- and Slack-style schemes.
- Control-case gating: if the valid request isn't accepted, the run is
  inconclusive and no further requests are sent.
- Configurable accept/reject matchers (status codes and/or body text).
- Terminal, JSON and Markdown reports, with credential-like headers redacted.
- Signing secret read from an environment variable, a file or a hidden prompt.
  It is never taken as a plain argument and never written to output.
- `sigaudit demo`: a local receiver with six switchable verification flaws.
- `sigaudit profiles` (list, show, or validate a file) and `sigaudit cases`.
- Exit codes for CI: 0 clean, 1 findings, 2 inconclusive, 3 refused/usage.

[Unreleased]: https://github.com/purplerock-ctrl/signature-verification-auditor/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/purplerock-ctrl/signature-verification-auditor/releases/tag/v0.1.0
