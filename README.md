# sigaudit: webhook signature verification auditor

[![CI](https://github.com/purplerock-ctrl/signature-verification-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/purplerock-ctrl/signature-verification-auditor/actions/workflows/ci.yml)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

`sigaudit` checks whether a webhook endpoint **actually verifies** the HMAC
signatures on incoming callbacks. It sends a small set of deliberately bad
requests (unsigned, forged, tampered, replayed) and reports every one the
endpoint **wrongly accepts**.

A correctly implemented endpoint rejects all of them. Every acceptance is a
finding. On a payment webhook, a finding can mean an attacker can send you a
convincing `payment succeeded` event for a payment that never happened.

```text
$ sigaudit demo
  1. Valid signature (control)         200  accepted  PASS
  2. No signature header               200  accepted  FINDING
  3. Empty signature value             200  accepted  FINDING
  4. Malformed signature               400  rejected  PASS
  5. Signed with the wrong secret      400  rejected  PASS
  6. Body modified after signing       400  rejected  PASS
  7. Replay with an old timestamp      200  accepted  FINDING
  8. Wrong hash algorithm              400  rejected  PASS

3 FINDINGS: the endpoint accepted requests it should have rejected.
```

---

## ⚠️ Authorized use only

> **Only test endpoints you own or are explicitly authorized to test.**
> Sending forged requests to a system without permission may be illegal
> (for example under the U.S. Computer Fraud and Abuse Act, the UK Computer
> Misuse Act, or equivalent laws elsewhere), even when the requests are harmless.

Appropriate targets:

- your own development or **staging** endpoint;
- a bug bounty target whose published policy puts the endpoint **in scope** and
  allows this kind of testing. Read the policy first. Many programs require an
  identifying header, which you can add with `-H`.

How the tool enforces this:

- **Nothing is sent until you confirm authorization**, either with
  `--i-am-authorized` or, interactively, by **typing the target's hostname**.
  Typing the hostname is stronger than a `y/N` prompt because it also catches
  pointing the tool at production when you meant staging.
- With no flag and no interactive terminal, it **refuses** to run.
- Every run prints a one-line legal reminder, and reports record how and when
  authorization was confirmed (plus an optional `--scope-note`).
- Requests go **one at a time at 1 per second** by default, with a hard
  ceiling of 5 per second. A full audit is at most 8 requests.
- The default request body is an inert, clearly labelled test event
  (`"type": "sigaudit.test"`).

**Important side effect:** if the endpoint *is* vulnerable, the forged
requests will be processed like real ones. That is what a finding means. Use
a staging environment, and if you supply your own payload, choose one that
does not trigger real business actions such as fulfilling an order.

---

## Contents

- [The bug class, explained](#the-bug-class-explained)
- [What it tests](#what-it-tests)
- [Install](#install)
- [Quick start: the demo](#quick-start-the-demo)
- [Usage](#usage)
- [Reading the results](#reading-the-results)
- [Adding a provider profile](#adding-a-provider-profile)
- [Limitations](#limitations)
- [Development](#development)

---

## The bug class, explained

### How webhook signing works

When a service such as Stripe, GitHub or Shopify calls your webhook, anyone
on the internet could have sent that HTTP request; your endpoint URL is not
a secret. To prove a request is genuine, the sender and receiver share a
**signing secret**. For every webhook the sender computes:

```text
signature = HMAC-SHA256(secret, <the exact bytes of the request body>)
```

and sends it in a header such as `X-Hub-Signature-256: sha256=5257a8...`.
Your endpoint recomputes the HMAC over the body it received, using its copy
of the secret, and compares the two values.

**HMAC** (hash-based message authentication code) has two properties that
matter here:

1. Without the secret, nobody can produce a valid signature for any body.
2. Change a single byte of the body and the signature no longer matches.

So a signature that verifies proves the request came from someone who holds
the secret, and that it was not modified in transit.

### Replay protection

A valid signature proves *who* sent a message, not *when*. An attacker who
captures one genuine request (from a log, a proxy, or a misconfigured debug
endpoint) could re-send it later, and its signature is still valid.
Providers such as Stripe and Slack therefore include a **timestamp in the
signed data**:

```text
signature = HMAC-SHA256(secret, "1700000000." + body)     # Stripe-style
```

Receivers reject anything older than a few minutes. Because the timestamp is
part of the signed string, an attacker cannot simply edit it. Deduplicating
on the event ID is the second layer of defence.

### What goes wrong

Every step above can be skipped or broken, and the endpoint will still
appear to work, because genuine webhooks are always validly signed. These
bugs only show up when someone sends a *bad* request, which nobody does
during normal testing. That is the gap this tool fills.

| Mistake in the receiver | What it looks like in code | Case that catches it |
|---|---|---|
| Verification is optional | `if sig: verify(sig)` | 2, 3 |
| Fails open on errors | `try: verify() except: pass` | 4 |
| Doesn't actually compare against the secret | wrong variable compared, stub left in, "monitor mode" that only logs | 5 |
| Signs a re-serialised body, or only part of it | `verify(json.dumps(request.json))` | 6 |
| No timestamp check | HMAC verified, timestamp ignored | 7 |
| Algorithm chosen from the request | `hashlib.new(header.split("=")[0])` | 8 |

### What correct verification looks like

The safest option is the provider's official SDK function (for example,
Stripe's `construct_event`). If you write it yourself, it should look like
this:

```python
import hashlib
import hmac
import time


def verify_stripe_style(raw_body: bytes, header: str, secret: bytes, tolerance: int = 300) -> bool:
    try:
        items = dict(part.split("=", 1) for part in header.split(","))
        timestamp = int(items["t"])
        received = bytes.fromhex(items["v1"])
    except (KeyError, ValueError):
        return False  # missing/malformed -> reject (fail closed)
    signed = f"{timestamp}.".encode() + raw_body  # the RAW bytes, never re-serialised JSON
    expected = hmac.new(secret, signed, hashlib.sha256).digest()  # algorithm fixed in code
    if not hmac.compare_digest(received, expected):  # constant-time comparison
        return False
    return abs(time.time() - timestamp) <= tolerance  # replay window
```

(Real providers can send several `v1=` values during secret rotation. This
simplified version keeps only the last one, which is one more reason to use
the official library.)

---

## What it tests

| # | Case ID | Request sent | Expected | Severity if accepted |
|---|---|---|---|---|
| 1 | `valid` | Correctly signed with your secret, fresh timestamp (**control**) | accept | n/a |
| 2 | `missing-signature` | No signature header | reject | critical |
| 3 | `empty-signature` | Signature header present but empty | reject | critical |
| 4 | `malformed-signature` | Correct header layout, garbage signature | reject | critical |
| 5 | `wrong-secret` | Well-formed signature made with a random key | reject | critical |
| 6 | `tampered-body` | Valid signature for the original body, modified body sent | reject | critical |
| 7 | `replay-old-timestamp` | Valid signature over a timestamp outside the tolerance | reject | high |
| 8 | `wrong-algorithm` | Signed with your secret using SHA-1 instead of SHA-256 | reject | medium |

Design notes:

- **Each case changes exactly one thing** from the valid request, so a
  finding points at one specific mistake.
- **Every request gets its own event ID** (`evt_sigaudit_<run>_<case>`).
  This makes requests easy to find in your logs. It also stops duplicate-event
  protection from rejecting, say, the replay case for the wrong reason and
  hiding a missing timestamp check.
- The **replay** case is skipped for profiles with no timestamp (GitHub- and
  Shopify-style schemes). Those schemes have no built-in replay protection,
  so deduplicating on event ID is your only defence there.

You can run `sigaudit cases` to list them from the CLI.

---

## Install

Requires Python 3.11+.

```bash
pip install git+https://github.com/purplerock-ctrl/signature-verification-auditor.git
```

To install a specific release (see [Releases](https://github.com/purplerock-ctrl/signature-verification-auditor/releases)
and the [changelog](CHANGELOG.md)):

```bash
pip install "git+https://github.com/purplerock-ctrl/signature-verification-auditor.git@v0.1.0"
```

or, from a clone, for development:

```bash
git clone https://github.com/purplerock-ctrl/signature-verification-auditor.git
cd signature-verification-auditor
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Runtime dependencies: `httpx`, `PyYAML`, `rich`.

---

## Quick start: the demo

The demo starts a deliberately broken receiver on `127.0.0.1` and audits it.
Nothing leaves your machine.

```bash
sigaudit demo                                     # two planted flaws, three findings
sigaudit demo --correct                           # a correct receiver: no findings
sigaudit demo --flaw fail-open --flaw accept-sha1 # choose the flaws
sigaudit demo --markdown-report demo.md           # see what a report looks like
```

Available flaws: `no-verification`, `skip-if-missing`, `fail-open`, `log-only`,
`no-timestamp-check`, `accept-sha1`.

---

## Usage

```text
sigaudit run URL --profile PROFILE [--secret-env VAR | --secret-file PATH]
             [--i-am-authorized] [--scope-note TEXT]
             [--rate N] [--timeout S] [--ca-bundle PATH] [-H 'Name: value']...
             [--payload-file PATH] [--only IDS] [--skip IDS] [--replay-age S]
             [--accept-status SPEC] [--accept-body TEXT]
             [--reject-status SPEC] [--reject-body TEXT]
             [--json-report PATH] [--markdown-report PATH] [--no-color]
```

### Supplying the signing secret

The tool needs your **test endpoint's** signing secret to build the valid
control request and the correctly signed negative cases. There is
deliberately **no `--secret VALUE` option**: values given as command-line
arguments end up in shell history and are visible to other users in `ps`.

```bash
# 1. from an environment variable
export WEBHOOK_SECRET='whsec_...'
sigaudit run https://staging.example.com/webhooks/stripe -p stripe --secret-env WEBHOOK_SECRET

# 2. from a file (you'll be warned if other users can read it)
sigaudit run https://staging.example.com/webhooks/stripe -p stripe --secret-file ~/.secrets/stripe-staging

# 3. neither: you're prompted with hidden input (interactive terminals only)
sigaudit run https://staging.example.com/webhooks/stripe -p stripe
```

The secret is never written to reports or terminal output.

### Examples

```bash
# Interactive: you'll be asked to type "staging.example.com" to confirm.
sigaudit run https://staging.example.com/webhooks/stripe -p stripe --secret-env WEBHOOK_SECRET

# GitHub-style endpoint, with both reports saved for a ticket.
sigaudit run https://ci.example.com/github-hook -p github --secret-env GH_HOOK_SECRET \
  --json-report audit.json --markdown-report audit.md

# Bug bounty target (in scope per the program policy), identified as the program requires.
sigaudit run https://hooks.target.example/payments -p stripe --secret-env TEST_ACCOUNT_SECRET \
  --i-am-authorized --scope-note "Target Corp program, payments webhook listed in scope" \
  -H "X-Bug-Bounty: your-handle"

# Run just a couple of cases.
sigaudit run URL -p stripe --secret-env S --only tampered-body,replay-old-timestamp

# Use your own payload; __SIGAUDIT_EVENT_ID__ is replaced per case.
sigaudit run URL -p generic-hmac-sha256 --secret-env S --payload-file examples/payload.json

# Staging with a private CA. (TLS verification is never switched off.)
sigaudit run https://staging.internal/hook -p slack --secret-env S --ca-bundle ./internal-ca.pem
```

### In CI

Use exit codes to gate a pipeline against staging after each deploy:

```bash
sigaudit run "$STAGING_WEBHOOK_URL" -p stripe --secret-env STAGING_WEBHOOK_SECRET \
  --i-am-authorized --scope-note "own staging, CI" --no-color \
  --json-report sigaudit-report.json
```

| Exit code | Meaning |
|---|---|
| `0` | Clean: control accepted, every bad request rejected |
| `1` | Findings: at least one bad request was accepted |
| `2` | Inconclusive: control not accepted, or errors/ambiguous responses |
| `3` | Refused: no authorization, or a usage/configuration error (nothing was sent) |

### When "2xx = accepted" is wrong for your app

By default, a 2xx status means *accepted* and anything else means
*rejected*. Some apps behave differently, for example by returning
`200 {"error": "invalid signature"}`. Describe your app's behaviour with
matchers:

```bash
# App returns 200 for everything, with an error message on rejection:
sigaudit run URL -p stripe --secret-env S --reject-body "invalid signature"

# App returns 202 on success and 401 on failure, and nothing else is expected:
sigaudit run URL -p stripe --secret-env S --accept-status 202 --reject-status 401
```

| You give | Behaviour |
|---|---|
| neither | 2xx = accepted, anything else = rejected |
| only `--accept-*` | matches = accepted, anything else = rejected |
| only `--reject-*` | matches = rejected; otherwise 2xx = accepted |
| both | strict: a response matching neither (or both) is **inconclusive**, never guessed |

Status specs accept `200`, `2xx`, `200-204` and comma-separated mixes such as `2xx,409`.

---

## Reading the results

| Verdict | Meaning |
|---|---|
| `PASS` | Behaved correctly (control accepted, or a bad request rejected) |
| `FINDING` | A bad request was **accepted** |
| `INCONCLUSIVE` | Can't be interpreted (see below) |
| `SKIPPED` | Not applicable to this profile (replay without a timestamp) |
| `ERROR` | No HTTP response (connection refused, timeout, TLS error) |

**The control case gates everything.** If the valid request is *not*
accepted, a rejected forgery proves nothing: maybe the endpoint rejects
everything, or the secret or profile is wrong. In that case the tool stops
after the control request, marks the rest `INCONCLUSIVE`, and exits `2`. This
rule is what stops a misconfigured run from looking like a clean bill of health.

Other things to know:

- **Redirects are not followed.** A `302` to a login page is a rejection,
  not a `200`.
- A **5xx** response to a bad request counts as a rejection, with a note:
  the verification code is probably throwing an unhandled exception and
  should return a clean 4xx.

### Reports

- `--markdown-report`: a self-contained write-up suitable for a bug report.
  It has a summary table, then each finding with its risk, a recommended fix,
  the **exact request sent** (as raw HTTP) and the **response received**.
- `--json-report`: the same data for tooling (`schema_version: 1`).

Headers that look like credentials (`Authorization`, `Cookie`, `*token*`,
`*secret*`, `*api-key*`) are redacted in reports. They are still sent on the
wire. Signature headers are not redacted, because an HMAC over a test payload
does not reveal the secret.

---

## Adding a provider profile

A profile describes how a service signs webhooks. Most header-based schemes
differ only in a few details, which the profile captures as two templates
plus some settings:

```yaml
# acme.yaml
name: acme                              # lowercase, digits, - or _
description: Acme Payments webhooks
algorithm: sha256                       # sha1 | sha256 | sha512
signed_payload: "{timestamp}.{body}"    # what is HMAC'd; {body} exactly once
signature_header: X-Acme-Signature
signature_format: "t={timestamp},sig={signature}"   # header value layout
signature_encoding: hex                 # hex | base64            (default hex)
secret_encoding: utf8                   # utf8 | hex | base64     (default utf8)
timestamp:                              # omit if the scheme has no timestamp
  tolerance_seconds: 300                # what a correct receiver should enforce
  header: X-Acme-Timestamp              # only if sent in a separate header
content_type: application/json          # default application/json
extra_headers:                          # optional, sent with every request
  X-Acme-Event: test.ping
references:
  - https://docs.acme.example/webhooks/verify
```

How the built-in profiles map onto these fields:

| Profile | `signed_payload` | `signature_format` | Encoding | Timestamp |
|---|---|---|---|---|
| `generic-hmac-sha256` | `{body}` | `{signature}` | hex | none |
| `github` | `{body}` | `sha256={signature}` | hex | none |
| `shopify` | `{body}` | `{signature}` | base64 | none |
| `stripe` | `{timestamp}.{body}` | `t={timestamp},v1={signature}` | hex | in signature header |
| `slack` | `v0:{timestamp}:{body}` | `v0={signature}` | hex | separate header |

Validate your file, then use it by path:

```bash
sigaudit profiles acme.yaml          # validates and explains the profile
sigaudit profiles stripe             # print a built-in profile as a starting point
sigaudit run URL --profile ./acme.yaml --secret-env ACME_SECRET
```

Profiles are validated strictly. Unknown keys (typos), a missing `{body}`,
or a timestamp that is sent but not signed (which gives no replay protection)
are rejected with a message saying what is wrong.

A fully annotated example is in [`examples/custom-profile.yaml`](examples/custom-profile.yaml).
To contribute a profile as a built-in, see [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Limitations

The tool is deliberately narrow. Things it does **not** do:

- **It sees HTTP responses, not your app's behaviour.** An endpoint that
  returns `200` and then discards the event in a background job will be
  reported as accepting it. Confirm in its logs using the event IDs.
- **Timing-unsafe comparison is not tested.** Comparing signatures with `==`
  instead of `hmac.compare_digest` is a real flaw, but it can't be measured
  reliably over a network with a handful of requests. Check for it in code review.
- **Header-based schemes only.** Schemes that put the signature *inside the
  body* or sign selected fields rather than the raw body (for example,
  Adyen's HMAC on notification items) are not supported yet.
- **One signature per request.** It does not test multi-signature headers
  used during secret rotation.

---

## Development

```bash
pip install -e ".[dev]"
pytest                    # unit + end-to-end tests against a local mock receiver
ruff check . && ruff format --check .
mypy                      # strict
```

The tests never touch the network: `src/sigaudit/demo_server.py` runs a
receiver on `127.0.0.1` that can verify correctly or with any combination of
the planted flaws. Its verification code is written independently of the
tool's own signer, so a signer bug can't hide by agreeing with itself. The
signer itself is checked against reference values produced with `openssl`.

```text
src/sigaudit/
  cli.py            argument parsing and orchestration
  authorization.py  the authorization gate
  profiles.py       provider profile model, loader and validation
  signing.py        pure HMAC signing functions
  cases.py          the eight audit cases
  classify.py       response -> accepted / rejected / unclear
  runner.py         rate-limited sending and verdicts
  results.py        result types and exit codes
  report/           terminal, JSON and Markdown output
  demo_server.py    local receiver with switchable flaws
  builtin_profiles/ shipped YAML profiles
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines and
[SECURITY.md](SECURITY.md) for reporting vulnerabilities in sigaudit itself.

## License

[MIT](LICENSE)
