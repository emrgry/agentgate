# Releasing AgentGate

End users install the Mac side with one line and never need Node.js, npm or git:

```bash
curl -fsSL https://github.com/emrgry/agentgate/releases/latest/download/install.sh | sh
```

A release is created by pushing a `v*` tag. `.github/workflows/release.yml` runs the CI
checks, builds every target on `ubuntu-latest`, signs the checksums and publishes a GitHub
release. Nothing is built or signed on a laptop.

## What a release contains

| Asset | What |
|---|---|
| `agentgate-<version>-darwin-arm64.tar.gz` | Apple silicon |
| `agentgate-<version>-darwin-x64.tar.gz` | Intel Macs |
| `agentgate-<version>-linux-{x64,arm64}.tar.gz` | CLI + server for Linux (no installer and no launchd `setup` yet; run `agentgate serve` yourself) |
| `SHA256SUMS` | SHA-256 of every tarball |
| `SHA256SUMS.sig` | Ed25519 signature over `"agentgate-release:v1\n" ‖ SHA256SUMS`, base64url |
| `install.sh` | the installer, with the release public key embedded |

Tarball layout (`scripts/build-release.mjs`):

```
bin/agentgate           POSIX launcher → libexec/node lib/agentgate.mjs (exit 77 if it can't start)
bin/agentgate-hook.sh   fail-closed Claude Code hook shim (only exit 0 or 2)
libexec/node            official Node.js runtime, pinned version + pinned SHA-256
lib/agentgate.mjs       esbuild bundle of the CLI, lib/api.mjs the local server, lib/chunk-*.mjs shared code
lib/pglite.{wasm,data}, lib/initdb.wasm   PGlite assets (loaded relative to the bundle)
lib/profiles/           built-in provider profiles
VERSION, LICENSE.md, THIRD_PARTY_LICENSES.txt, libexec/NODE_LICENSE
```

There are no runtime `node_modules`: everything is bundled. Optional native accelerators
(`bufferutil`, `utf-8-validate`, `pg-native`) are left out on purpose; their callers fall back
to pure JS. The build is deterministic (fixed tar metadata, mtime = HEAD commit time or
`SOURCE_DATE_EPOCH`), so rebuilding a tag gives byte-identical tarballs.

The embedded Node.js is pinned in `scripts/build-release.mjs` (`NODE_VERSION` + one SHA-256
per target, copied from nodejs.org's `SHASUMS256.txt`, which the build also cross-checks).
Downloads are cached in `.cache/node` (CI caches it too). To bump Node, change the version
and all four hashes together. The darwin binaries are Node's own signed and notarized
builds, and files fetched by `curl` carry no quarantine flag, so Gatekeeper does not prompt.

## Trust model

- **First install** trusts GitHub's TLS: `install.sh` and the assets come from
  `github.com/emrgry/agentgate/releases`. The installer always checks the tarball against
  `SHA256SUMS`. It also verifies `SHA256SUMS.sig` with the embedded public key when an
  OpenSSL 3 binary is available (Homebrew's `openssl@3`; macOS's LibreSSL can't do it).
  `AGENTGATE_REQUIRE_SIGNATURE=1` makes that mandatory.
- **Every update** (`agentgate update`) requires a valid signature by the public key compiled
  into the installed CLI (`daemon/agentgate/src/release-key.ts`). No signature, a wrong key,
  a modified `SHA256SUMS` or a tarball that doesn't match its checksum means nothing is
  installed. A newer "latest" is required unless `--version` is given explicitly (no silent
  downgrades). There is no runtime override for the key.
- Agents can't run `agentgate update|uninstall|setup|restart` (hook guard) or write to
  `~/.agentgate` (including `versions/`, `current`, `previous`) or `~/.local/bin/agentgate`.

## One-time setup (before the first public release)

1. **Generate the release key** on a trusted machine:

   ```bash
   node scripts/gen-release-key.mjs --seed
   ```

   It prints the public key on the first stdout line and the secret seed on the second. It
   writes nothing to disk. Store the seed in a password manager as a backup. Anyone holding
   it can publish updates that every AgentGate install will accept.

2. **Add the GitHub secret** `AGENTGATE_RELEASE_SIGNING_KEY` (repository → Settings →
   Secrets and variables → Actions), value = the seed. With the GitHub CLI, without the seed
   touching your shell history or a file:

   ```bash
   node scripts/gen-release-key.mjs --seed | tee /dev/stderr | tail -n 1 | gh secret set AGENTGATE_RELEASE_SIGNING_KEY
   ```

   (`tee /dev/stderr` shows you both lines once so you can copy the public key and back up the seed.)

3. **Pin the public key** in `daemon/agentgate/src/release-key.ts`:

   ```ts
   export const SOURCE_RELEASE_PUBLIC_KEY = "<public key from step 1>";
   ```

   Commit it. Until you do, the release workflow refuses to build
   (`--require-release-key`), and builds made with the placeholder refuse every update.
   `scripts/sign-release.mjs` also refuses to sign when the seed doesn't match the pinned
   key, so a mismatched release can't be published.

Rotating the key later means shipping one release that is signed by the old key and embeds
the new one. Installs that skip that release have to re-run the one-line installer.

## Cutting a release

1. Bump the version in **both** `package.json` and `daemon/agentgate/src/version.ts`
   (`SOURCE_VERSION`; the build fails if they differ). Commit and push.
2. Tag and push:

   ```bash
   git tag v0.2.0 && git push origin v0.2.0
   ```

3. Watch the **Release** workflow. It runs typecheck + vitest + API tests and a Linux bundle
   smoke test, checks that the tag equals `v<package.json version>`, builds all targets,
   signs `SHA256SUMS`, smoke-tests the linux-x64 tarball and creates the GitHub release.
4. On a Mac: `agentgate update --check` on an existing install, or run the one-liner in a
   fresh user account.

## Building and testing locally

```bash
npm run build:release                                  # darwin-arm64 + darwin-x64 → dist/release
node scripts/build-release.mjs --all                   # + linux-x64, linux-arm64
node scripts/build-release.mjs --targets darwin-arm64 --out /tmp/rel
AGENTGATE_RELEASE_SIGNING_KEY=… npm run sign:release   # → dist/release/SHA256SUMS.sig
npm run test:release-e2e                               # macOS: full install/update/rollback/uninstall in a temp HOME
```

Local builds without `AGENTGATE_RELEASE_PUBLIC_KEY` use the placeholder key and print a
warning. The e2e test generates a throw-away key, builds with
`AGENTGATE_RELEASE_PUBLIC_KEY=<it>`, serves the release from a `file://` tree through
`AGENTGATE_RELEASE_BASE_URL`, and uses the fake `launchctl` test seam. It never touches your
real `~/.agentgate` or launchd.

`AGENTGATE_RELEASE_BASE_URL` (installer and `agentgate update`) points at a mirror with the
GitHub layout: `<base>/latest/download/<asset>` and `<base>/download/v<version>/<asset>`.
`agentgate update` accepts https, `file:` and loopback http only. The signature is still
required.
