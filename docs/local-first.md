# M7 — Local-first AgentGate

Decision (2026-09-26): AgentGate runs **on the developer's own machine**. No hosted
backend, no accounts, ~zero cloud cost. The phone pairs by scanning a QR code; the
QR *is* the identity exchange.

```
 Developer machine (always on while agents run)            iPhone (App Store app)
 ┌───────────────────────────────────────────┐   LAN / Tailscale (phase 1)
 │ agentgate daemon (launchd)                │◀──────────────────────────▶  scan QR → pair
 │  ├─ embedded API + PGlite (~/.agentgate)  │   E2E-encrypted relay (phase 2)
 │  ├─ policy engine, hooks, MCP gateway     │◀─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶  approve (Face ID)
 │  └─ Expo push (direct, content-free)      │
 └───────────────────────────────────────────┘
```

## First run
1. `brew install agentgate` (phase 3; today: build from source, see README)
2. `agentgate setup` → installs/starts the local server as a launchd agent, creates
   the local owner identity, prints a QR.
3. Phone: install AgentGate → **Scan QR** → paired (one tap).
4. `agentgate install claude-code` / `agentgate mcp install …`

## Trust model
- **Owner identity**: the machine owner. No email/password. Agent login is loopback-only
  (the agent runs on the same machine as the server).
- **Server identity key** (Ed25519, already exists as the "approval signing key"): its
  fingerprint is in the QR. The phone pins it at pairing and requires the server to prove
  possession (`POST /v1/pairing/hello` challenge) → pairing with a MITM fails.
- **Device key** (Ed25519, generated on the phone at pairing, private key in the iOS
  Keychain with biometric access control). Registered with the server during pairing.
- **Approvals are signed by the phone** (`SignedDecision`, v2). The executor (hook /
  `agentgate exec` / MCP gateway) verifies the phone's signature against the pinned
  device key. The server only relays; a compromised server/relay/agent cannot forge an
  approval. Server-signed v1 tokens remain accepted only for devices paired before M7
  (no device key) and can be disabled with `AGENTGATE_REQUIRE_DEVICE_SIGNATURES=1`.
- A second phone is still approved by an already-paired phone (existing flow). A second
  computer runs its own server; the phone holds one pairing per computer.

## Transport
- Phase 1: direct HTTP/WS to the machine (same Wi-Fi, or Tailscale if the developer uses
  it). Push notifications are sent by the local server straight to Expo Push; bodies are
  content-free ("<Agent> needs approval · HIGH").
- Phase 2: optional relay (Cloudflare Worker + Durable Object, free tier). Rooms keyed by
  pairing id; payloads end-to-end encrypted with a key derived from the QR secret. The
  relay sees only ciphertext and timing.
- Phase 3: distribution — Homebrew/npm package, App Store/TestFlight build.

## Out of scope (for now)
Hosted multi-tenant backend, email auth, teams.

## Session lifetime (phone)
- Access token: 12 h (`aud: device`, bound to the device id). Refresh token: 90 days,
  **sliding** — every rotation restarts the 90 days. Agents: 1 h access / 30 d refresh.
- Every device-bound `LoginResponse` carries `refresh_token`: pairing-code login (200), the
  approved pairing request poll (`login`), and `POST /v1/devices/:id/rekey`.
- The phone refreshes **silently** via `POST /v1/auth/refresh {refresh_token}` → `{access_token,
  expires_at, refresh_token, device_id}` (same device binding). Single use; replaying a rotated
  token revokes the family (401 `refresh_token_reused`).
- **An expired access token is not "unpaired".** Only 401 `device_revoked` (device revoked,
  local recovery revoke/reset) means the pairing is gone → pair again. Other refresh
  failures (`refresh_token_revoked | _reused | _expired`, `invalid_refresh_token`) mean the
  session is gone but the device record may still be active → hello with `device_id`
  (`already_paired: true`) → rekey, which returns a fresh refresh family.
- Revoking a device (any path) revokes its refresh families; a rekey revokes the device's
  older families and issues a new one.

## Re-pairing and recovery (device key rotation)

**The deadlock this fixes.** A phone that is already paired scans a new `agentgate pair`
QR. The login returns 202 because another active device exists, but that device is the
phone's own old record, so nobody can approve the request.

**1. Rekey: same phone, old key still in the Keychain.**
- `POST /v1/pairing/hello {challenge, device_id?}` answers `already_paired: true` when
  `device_id` is an active device here. The phone then rekeys instead of pairing again.
- `POST /v1/devices/:id/rekey` is public; the signature is the proof. The body is a
  `RekeyRequest` (packages/protocol, local-first.ts):
  `{device_id, new_public_key, issued_at, expires_at, nonce, signature}`.
  - `signature` = Ed25519 with the **old** key over the UTF-8 bytes of
    `"agentgate-rekey:v1:" + canonicalJson({device_id, new_public_key, issued_at, expires_at, nonce})`.
  - `expires_at − issued_at ≤ 5 min`, and the nonce is single use (`used_nonces` table).
  - Helpers: `signRekey(payload, oldPrivateKey) → RekeyRequest` and
    `verifyRekey(req, {publicKeyFor, now?, nonceStore?, signatureOnly?})` in `@agentgate/signing`.
- The server checks that the device exists, isn't revoked and has a key; verifies the
  signature, lifetime and new key (≠ old, not used by another device); consumes the nonce;
  then compare-and-swaps the key. It stores `rekeyed_at` and the proof, audits
  `device.rekeyed`, and returns a device-bound `LoginResponse` (same `device_id`).
  - From then on, decisions and commands signed with the old key fail.
  - Errors: 403 `rekey_rejected` (the reason is in the message), 403 `device_revoked`,
    409 `key_in_use` / `rekey_conflict`, 400 `device_mismatch`.
- **Executors** (`~/.agentgate/device-keys.json`): a changed key for a pinned device is accepted
  only when the server reports `rekeyed_at` **newer than the pin** and a `rekey_proof` that
  verifies against the **pinned (old) key** and names exactly the new key. Both come from
  `GET /v1/devices/keys` (`rekeyed_at`, `rekey_proof`), so the server alone can't forge a
  rotation. Otherwise the old refusal stands. That includes rotations the executor missed
  (key A → B → C seen as A → C); remove the pin to re-trust in that case.

**2. Recovery: key lost, nobody can approve.**
- Commands: `agentgate devices list | revoke <id> | reset`.
  - `list` needs no extra proof: it calls `GET /v1/devices` with the agent token, loopback only.
  - `revoke` and `reset` need **human presence**. The CLI:
    1. runs `sudo -v` (password or Touch ID) and fails closed if that doesn't succeed;
    2. via `sudo -n`, writes a random one-time nonce into a **root-owned** file
       `/tmp/agentgate-recovery-<random>` (noclobber, mode 0644);
    3. calls `POST /v1/devices/recovery {action, device_id?, nonce, proof_path}` (agent token,
       loopback only);
    4. removes the file.
- The server accepts the request only if the proof file matches the name pattern, is a
  regular file (not a symlink), is owned by **uid 0**, isn't group/other-writable, is fresh
  (≤ 5 min), and contains the nonce. The nonce is single use.
- An agent with the user's agent token can't produce a uid-0 file without sudo. On macOS
  sudo's `tty_tickets` also stop it from reusing the user's sudo timestamp from another
  terminal.
- Agents are additionally blocked from running `agentgate devices` by the hook guard
  (Claude, Codex and generic hooks), and from calling `/v1/devices…` directly.
- `reset` revokes every device and expires pending pairing requests, so the next pairing is
  a bootstrap. It is audited as `device.recovery_reset`. `revoke` revokes one device and is
  audited as `device.revoked` with `by: local_recovery`.
