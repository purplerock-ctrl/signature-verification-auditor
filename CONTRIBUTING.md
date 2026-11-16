# Contributing to sigaudit

Thanks for helping. Contributions of all sizes are welcome: new provider
profiles, bug fixes, docs, tests.

## Ground rules for a security tool

sigaudit exists to help people check systems **they are authorized to test**.
Contributions that weaken that are out of scope and will be declined, including:

- removing or bypassing the authorization gate, or making it opt-out by default;
- raising or removing the request-rate ceiling, or adding concurrency;
- scanning many targets, target discovery, or any kind of crawling;
- evading detection, e.g. disguising the User-Agent or randomising
  fingerprints by default.

If you're unsure whether an idea fits, open an issue first.

## Development setup

```bash
git clone https://github.com/purplerock-ctrl/signature-verification-auditor.git
cd signature-verification-auditor
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Before opening a pull request, run everything CI runs:

```bash
ruff check . && ruff format --check .
mypy
pytest --cov=sigaudit
```

Tests must not touch the network. Use the local receiver in
`src/sigaudit/demo_server.py` (see the `make_receiver` fixture in
`tests/conftest.py`) or `httpx.MockTransport`.

## Adding a built-in provider profile

1. Add `src/sigaudit/builtin_profiles/<name>.yaml`. Start from
   `examples/custom-profile.yaml` and include a `references:` link to the
   provider's official verification docs.
2. Check it: `sigaudit profiles src/sigaudit/builtin_profiles/<name>.yaml`.
3. Add a **reference test vector** to `tests/test_signing.py`
   (`test_builtin_profiles_produce_reference_headers`). Compute the expected
   value with an independent tool, not with sigaudit itself, for example:

   ```bash
   printf '%s' '1700000000.{"id":"evt_1","amount":100}' \
     | openssl dgst -sha256 -hmac 'whsec_test_secret'
   ```

   Use base64 (`-binary | base64`) if the provider uses base64. If the
   provider publishes an official example signature, test against that instead.
4. Update the profile table in the README.

## Adding or changing an audit case

A new case needs all of:

- a builder and an `AuditCase` entry in `src/sigaudit/cases.py`, with a
  one-line `risk` and `fix`;
- a realistic `Flaw` in `src/sigaudit/demo_server.py` that the case detects;
- a row in the `EXPECTED` table in `tests/test_runner.py` that asserts the
  flaw produces **exactly** the expected findings, and that a correct
  receiver produces none;
- an update to the "What it tests" table in the README.

## Style

- Type hints everywhere; `mypy --strict` must pass.
- `ruff format` for formatting.
- Keep runtime dependencies minimal; a new dependency needs a good reason.
- Comments explain *why*. Security-relevant decisions deserve a sentence.

## Releasing (maintainers)

1. In a pull request, bump `__version__` in `src/sigaudit/__init__.py` and
   move the `[Unreleased]` entries in `CHANGELOG.md` under a new
   `## [X.Y.Z] - YYYY-MM-DD` heading. Update the comparison links at the bottom.
2. Merge it once CI is green.
3. Tag the merge commit on `main` and push the tag:

   ```bash
   git tag -a vX.Y.Z -m "sigaudit vX.Y.Z"
   git push origin vX.Y.Z
   ```

The `Release` workflow then checks the tag matches the package version, runs
the tests, builds the sdist and wheel, and publishes a GitHub Release using
that version's changelog section as the notes.

## Commit messages and pull requests

Small, focused PRs are easiest to review. Describe what changed and why, and
mention how you tested it.
