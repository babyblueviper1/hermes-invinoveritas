# invinoveritas-receipts for Hermes Agent

A signed, independently checkable receipt for each Hermes approval verdict.

When Hermes runs with `approvals.mode: smart`, its Guardian LLM approves or denies dangerous commands on its own,
including in cron, webhook and other unattended sessions. That verdict is real, but it is self-graded and leaves
no record anyone outside the machine can check: later you cannot show what the Guardian decided, or when.

This plugin listens on Hermes's documented `post_approval_response` hook. For each Guardian verdict, it asks
[invinoveritas](https://invinoveritas.dev) for a **decision receipt**: a signed record that commits to the
decision without revealing it. The signed receipt holds salted hashes of the question, the options, the decision
context and the choice, plus the issue time. It does not hold the command or the choice in plain text.

Anyone can check the signature for free, without an account:
`POST https://api.babyblueviper.com/verify-proof` with the receipt's `event`.
You alone hold the salt. You can later hand over the salt and the context, and anyone can recompute that this
exact decision was recorded at that time.

## What it does and does not do

- **Observe-only.** It never approves, denies, delays or changes an approval. The hook returns nothing, never
  raises into Hermes, and makes its network call on a background thread.
- **Scope.** By default (`scope: guardian`) it records only Guardian LLM verdicts (`decided_by: aux_llm`).
  With `scope: all` it also records human approve/deny decisions. Timeouts, cancellations, escalations and
  notification failures are not decisions, so they get no receipt.
- **It does not judge the command.** A receipt attests that this decision was committed at that time. It does
  not say the decision was right.

## Disclosure

- **Network calls.** One HTTPS POST to `https://api.babyblueviper.com/decision-receipt` per recorded decision
  (configurable with `api_url`). Nothing else is called.
- **What is sent.** A fixed question, the options `["approve", "deny"]`, the choice, and the SHA-256 of the
  decision context, plus `decider: {provider: "hermes-agent", model: "guardian-llm" | "human", request_id:
  <tool_call_id>}`. The command, description and session key are **not** sent. The context hash includes a
  32-byte random nonce generated on your machine, so the hash cannot be reversed by guessing the command.
- **What is stored locally.** `<HERMES_HOME>/plugin-data/invinoveritas-receipts/receipts.jsonl`: the signed
  receipt, the salt, the nonce and the decision context (with the command as Hermes passed it to the hook;
  Hermes redacts secrets in Guardian commands). This file is what lets you open a receipt later, so keep it.
- **Credential.** Reads `INVINOVERITAS_API_KEY` only. Without it, Hermes does not load the plugin.
- **Cost.** Receipts are paid per call: 100 sats each, from your invinoveritas balance (Lightning, USDC via
  x402, or card). Registration is free. No telemetry, no background process beyond the per-receipt thread.

## Install

```bash
hermes plugins install https://github.com/babyblueviper1/hermes-invinoveritas
# prompted for INVINOVERITAS_API_KEY (free key: POST https://api.babyblueviper.com/register)
```

Settings live under `plugins.entries.invinoveritas-receipts.settings`:

| Key | Default | Meaning |
|---|---|---|
| `scope` | `guardian` | `guardian` = Guardian LLM verdicts only; `all` = every approve/deny decision |
| `api_url` | `https://api.babyblueviper.com` | invinoveritas API base |
| `timeout_s` | `10.0` | HTTP timeout for one receipt request |

## Checking and opening a receipt

Each line of `receipts.jsonl` holds `event`, `receipt`, `salt`, `choice`, `context` and `context_sha256`.

- **Signature:** `POST /verify-proof` with `{"event": <event>}`. Expect `valid: true`.
- **Context:** `sha256(canonical_json(context)) == context_sha256`, where canonical JSON is sorted keys with no
  spaces.
- **Commitments:** `sha256(salt + "|" + choice) == receipt.choice_commitment` and
  `sha256(salt + "|" + context_sha256) == receipt.context_commitment`.

## Development

```bash
python -m pytest            # 8 tests, no network
hermes plugins validate .   # Hermes's own catalog check
```

MIT license. Built by [invinoveritas](https://invinoveritas.dev), a verification layer for autonomous agents.
