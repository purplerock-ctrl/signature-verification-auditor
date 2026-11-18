# Case study: auditing a Stripe webhook receiver

A small Flask app ([`app.py`](app.py)) with two Stripe webhook endpoints. Both
accept every genuine Stripe event, so in normal use you can't tell them apart.
sigaudit can.

| Endpoint | How it verifies signatures |
|---|---|
| `POST /webhook` | Stripe's official library, `stripe.Webhook.construct_event`, as Stripe's docs recommend |
| `POST /webhook-naive` | Hand-written code with two mistakes that are common in real apps |

Everything runs on your machine (127.0.0.1). No hosting, no Stripe account
and no one else's system is involved.

## 1. Set up

From the repository root:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[examples]"
```

That installs sigaudit plus Flask and the Stripe library.

## 2. Start the receiver

```bash
cd examples/stripe-receiver
export STRIPE_WEBHOOK_SECRET=whsec_local_example_secret
python app.py
```

Leave it running. It listens on `http://127.0.0.1:4242` and logs a line for
every event it **processes**. Open a second terminal for the next steps, and
run the same `export` line there too.

(Putting a secret in `export` is fine for this throwaway example secret. For a
real one, leave out `--secret-env` and sigaudit asks for it with hidden input.)

## 3. Audit the correct endpoint

```bash
sigaudit run http://127.0.0.1:4242/webhook -p stripe --secret-env STRIPE_WEBHOOK_SECRET
```

Type `127.0.0.1` when asked to confirm. Expected result:

```text
  1. Valid signature (control)         200  accepted  PASS
  2. No signature header               400  rejected  PASS
  ...
  8. Wrong hash algorithm              400  rejected  PASS

No findings: every bad request was rejected and the valid control was accepted.
```

Stripe's own library accepted sigaudit's valid request and rejected all seven
bad ones.

## 4. Audit the naive endpoint

```bash
sigaudit run http://127.0.0.1:4242/webhook-naive -p stripe --secret-env STRIPE_WEBHOOK_SECRET \
  --markdown-report naive-report.md
```

```text
  1. Valid signature (control)         200  accepted  PASS
  2. No signature header               200  accepted  FINDING
  3. Empty signature value             200  accepted  FINDING
  4. Malformed signature               400  rejected  PASS
  5. Signed with the wrong secret      400  rejected  PASS
  6. Body modified after signing       400  rejected  PASS
  7. Replay with an old timestamp      200  accepted  FINDING

3 FINDINGS: the endpoint accepted requests it should have rejected.
```

## 5. Confirm in the receiver's log

A 200 response suggests the event was processed, but the log proves it. Look
at the first terminal:

```text
[webhook-naive] PROCESSED event evt_sigaudit_9e4ee2ce_valid (type sigaudit.test)
[webhook-naive] PROCESSED event evt_sigaudit_9e4ee2ce_missing_signature (type sigaudit.test)
[webhook-naive] PROCESSED event evt_sigaudit_9e4ee2ce_empty_signature (type sigaudit.test)
[webhook-naive] PROCESSED event evt_sigaudit_9e4ee2ce_replay_old_timestamp (type sigaudit.test)
```

Three forged events reached the business logic. In a real payments app,
`handle_event` would be the code that fulfils orders.

## 6. Fix it yourself

Edit `webhook_naive()` in `app.py` so it passes the audit. The two mistakes
are marked `MISTAKE 1` and `MISTAKE 2`, and `naive-report.md` has a
"Recommended fix" for each finding. Restart the app, then re-run step 4 until
you get `No findings`.

<details>
<summary>One possible fix (try it yourself first)</summary>

Replace everything from `if sig_header:` down to (not including) the
`handle_event` call with the code below, and add `import time` at the top.

```python
        try:
            parts = dict(item.split("=", 1) for item in (sig_header or "").split(","))
            timestamp = int(parts["t"])
            received = parts["v1"]
        except (KeyError, ValueError):
            return jsonify(error="invalid signature"), 400  # missing/empty/malformed

        signed = f"{timestamp}.".encode() + payload
        expected = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected.encode(), received.encode()):
            return jsonify(error="invalid signature"), 400
        if abs(time.time() - timestamp) > 300:
            return jsonify(error="timestamp outside tolerance"), 400
```

What changed:

- A missing or empty header now **fails** instead of skipping the check (fail closed).
- The signed timestamp must be within 5 minutes of now.

Comparing bytes rather than strings also avoids a `TypeError` (a 500 error) if
someone sends non-ASCII characters in the header. Even so, the real lesson is
the `/webhook` endpoint: use the provider's library and none of this is your
problem.

</details>

## 7. Optional: send genuine Stripe events

To check the receiver handles **real** Stripe traffic, not just sigaudit's
idea of a valid request, use a free Stripe account in **test mode** and the
[Stripe CLI](https://docs.stripe.com/stripe-cli):

```bash
stripe login
stripe listen --forward-to 127.0.0.1:4242/webhook
```

`stripe listen` prints a signing secret (`whsec_...`). Restart the app with
`STRIPE_WEBHOOK_SECRET` set to it, then in another terminal:

```bash
stripe trigger payment_intent.succeeded
```

The app logs `PROCESSED event evt_... (type payment_intent.succeeded)` and the
CLI shows `[200]`. Re-run the step 3 audit with the same secret and it still
passes: genuine events get in, forged ones don't.

## How this stays accurate

`tests/test_example_receiver.py` runs this same audit in CI. It checks that
`/webhook` has no findings, which also proves Stripe's own library accepts
sigaudit's signatures, and that `/webhook-naive` produces exactly the three
findings shown above.
