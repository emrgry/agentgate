/**
 * Public key that verifies AgentGate release signatures (SHA256SUMS.sig).
 *
 * `agentgate update` refuses any release whose SHA256SUMS is not signed by this key
 * (fail closed). The private half lives ONLY in the GitHub Actions secret
 * AGENTGATE_RELEASE_SIGNING_KEY; see docs/releasing.md.
 *
 * TODO(before the first public release): replace DEV_PLACEHOLDER_RELEASE_PUBLIC_KEY below
 * with the output of `node scripts/gen-release-key.mjs` (public key line). The placeholder's
 * private seed was discarded when it was generated, so NOTHING can be signed for it: until
 * it is replaced, `agentgate update` fails closed and `npm run build:release --
 * --require-release-key` (used by the release workflow) refuses to build.
 *
 * A build may override the key without editing this file:
 *   AGENTGATE_RELEASE_PUBLIC_KEY=<base64url> npm run build:release
 * (esbuild `define` → __AGENTGATE_RELEASE_PUBKEY__). There is deliberately NO runtime
 * override: an environment variable must never be able to change what `update` trusts.
 */
export const DEV_PLACEHOLDER_RELEASE_PUBLIC_KEY = "slciBkWzOpQWspWOUiCTJZMj8mjj9PJ1gcdy4valAGw";

/** The key embedded in the source tree (read by scripts/build-release.mjs). */
export const SOURCE_RELEASE_PUBLIC_KEY = DEV_PLACEHOLDER_RELEASE_PUBLIC_KEY;

declare const __AGENTGATE_RELEASE_PUBKEY__: string | undefined;

/** Key this build trusts (build-time override, else the source constant). */
export const RELEASE_PUBLIC_KEY: string = typeof __AGENTGATE_RELEASE_PUBKEY__ === "string" ? __AGENTGATE_RELEASE_PUBKEY__ : SOURCE_RELEASE_PUBLIC_KEY;

export const isPlaceholderReleaseKey = (key: string = RELEASE_PUBLIC_KEY) => key === DEV_PLACEHOLDER_RELEASE_PUBLIC_KEY;
