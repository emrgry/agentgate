/**
 * Public key that verifies AgentGate release signatures (SHA256SUMS.sig).
 *
 * `agentgate update` refuses any release whose SHA256SUMS is not signed by this key
 * (fail closed). The private half lives ONLY in the GitHub Actions secret
 * AGENTGATE_RELEASE_SIGNING_KEY; see docs/releasing.md.
 *
 * DEV_PLACEHOLDER_RELEASE_PUBLIC_KEY is kept only so tests and dev builds can recognize an
 * unsigned setup: its private seed was discarded, so nothing can ever be signed for it.
 *
 * A build may override the key without editing this file:
 *   AGENTGATE_RELEASE_PUBLIC_KEY=<base64url> npm run build:release
 * (esbuild `define` → __AGENTGATE_RELEASE_PUBKEY__). There is deliberately NO runtime
 * override: an environment variable must never be able to change what `update` trusts.
 */
export const DEV_PLACEHOLDER_RELEASE_PUBLIC_KEY = "slciBkWzOpQWspWOUiCTJZMj8mjj9PJ1gcdy4valAGw";

/**
 * The official AgentGate release key (generated 2026-09-28), embedded in the source tree and
 * read by scripts/build-release.mjs. Rotating it needs a release signed by the old key first.
 */
export const SOURCE_RELEASE_PUBLIC_KEY = "H89mNqez-uuAI37mD4u5UQWXRi7ew7rcTcu6FWBvVQo";

declare const __AGENTGATE_RELEASE_PUBKEY__: string | undefined;

/** Key this build trusts (build-time override, else the source constant). */
export const RELEASE_PUBLIC_KEY: string = typeof __AGENTGATE_RELEASE_PUBKEY__ === "string" ? __AGENTGATE_RELEASE_PUBKEY__ : SOURCE_RELEASE_PUBLIC_KEY;

export const isPlaceholderReleaseKey = (key: string = RELEASE_PUBLIC_KEY) => key === DEV_PLACEHOLDER_RELEASE_PUBLIC_KEY;
