#!/bin/sh
# AgentGate installer: macOS (Apple silicon / Intel), no sudo, no Node/npm/git needed.
#
#   curl -fsSL https://github.com/emrgry/agentgate/releases/latest/download/install.sh | sh
#
# What it does:
#   1. downloads agentgate-<version>-darwin-<arch>.tar.gz + SHA256SUMS (+ SHA256SUMS.sig)
#   2. verifies the SHA-256 checksum (always) and the Ed25519 release signature (when an
#      OpenSSL 3 binary is available; AGENTGATE_REQUIRE_SIGNATURE=1 makes it mandatory)
#   3. extracts it to ~/.agentgate/versions/<version>/ and points ~/.agentgate/current at it
#   4. writes ~/.local/bin/agentgate (a tiny shim → ~/.agentgate/current/bin/agentgate)
#   5. runs `agentgate setup` (local server + pairing QR); on re-runs it restarts the
#      server instead when no agent session is running
#
# Trust model: this first install trusts GitHub's TLS (plus the checksum and, if possible,
# the signature). Every later `agentgate update` REQUIRES a valid signature by the release
# key pinned inside the installed CLI.
#
# Options: --no-setup   install only          --version X   install a specific version
#          --dry-run    print what would happen, change nothing
# Env:     AGENTGATE_VERSION, AGENTGATE_INSTALL_DIR (~/.agentgate), AGENTGATE_BIN_DIR
#          (~/.local/bin), AGENTGATE_RELEASE_BASE_URL (mirrors/tests), AGENTGATE_REQUIRE_SIGNATURE=1
set -eu

# Replaced with the release public key (PEM) by scripts/build-release.mjs.
RELEASE_PUBKEY_PEM='__AGENTGATE_RELEASE_PUBKEY_PEM__'

BASE_URL="${AGENTGATE_RELEASE_BASE_URL:-https://github.com/emrgry/agentgate/releases}"
VERSION="${AGENTGATE_VERSION:-latest}"
INSTALL_DIR="${AGENTGATE_INSTALL_DIR:-$HOME/.agentgate}"
BIN_DIR="${AGENTGATE_BIN_DIR:-$HOME/.local/bin}"
REQUIRE_SIG="${AGENTGATE_REQUIRE_SIGNATURE:-0}"
RUN_SETUP=1
DRY_RUN=0
SHIM_MARKER="# agentgate-path-shim"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  B="$(printf '\033[1m')"; G="$(printf '\033[32m')"; Y="$(printf '\033[33m')"; R="$(printf '\033[31m')"; D="$(printf '\033[2m')"; N="$(printf '\033[0m')"
else
  B=""; G=""; Y=""; R=""; D=""; N=""
fi
say() { printf '%s\n' "$*"; }
ok() { printf '%s✔%s %s\n' "$G" "$N" "$*"; }
warn() { printf '%s!%s %s\n' "$Y" "$N" "$*" >&2; }
die() {
  printf '%s✘ %s%s\n' "$R" "$*" "$N" >&2
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --no-setup) RUN_SETUP=0 ;;
    --dry-run) DRY_RUN=1 ;;
    --version) [ $# -ge 2 ] || die "--version needs a value"; VERSION="$2"; shift ;;
    --version=*) VERSION="${1#--version=}" ;;
    -h | --help) sed -n '2,26p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
  shift
done

VERSION="${VERSION#v}"
if [ "$VERSION" != "latest" ]; then
  printf '%s' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.]*)?$' || die "invalid version: $VERSION"
fi
[ "$(id -u)" != 0 ] || die "do not run the AgentGate installer as root (no sudo needed)"
[ -n "${HOME:-}" ] || die "HOME is not set"
case "$INSTALL_DIR$BIN_DIR" in *"'"*) die "install paths must not contain a single quote" ;; esac

# ── platform ────────────────────────────────────────────────────────────────
OS="$(uname -s)"
[ "$OS" = "Darwin" ] || die "AgentGate's installer supports macOS only for now (found $OS). On Linux, build from source: https://github.com/emrgry/agentgate#development"
case "$(uname -m)" in
  arm64) ARCH=arm64 ;;
  x86_64)
    # An x86_64 shell under Rosetta on Apple silicon still gets the native build.
    if [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = 1 ]; then ARCH=arm64; else ARCH=x64; fi ;;
  *) die "unsupported CPU architecture: $(uname -m)" ;;
esac
TARGET="darwin-$ARCH"

for cmd in curl tar shasum mktemp; do
  command -v "$cmd" >/dev/null 2>&1 || die "missing required tool: $cmd"
done

if [ "$VERSION" = latest ]; then ASSETS="$BASE_URL/latest/download"; else ASSETS="$BASE_URL/download/v$VERSION"; fi

if [ "$DRY_RUN" = 1 ]; then
  say "${B}AgentGate installer (dry run: nothing is downloaded or changed)${N}"
  say "  platform        $TARGET"
  say "  release         $VERSION  ($ASSETS)"
  say "  download        $ASSETS/SHA256SUMS, SHA256SUMS.sig, agentgate-<version>-$TARGET.tar.gz"
  say "  verify          SHA-256 checksum; Ed25519 signature if OpenSSL 3 is available"
  say "  extract to      $INSTALL_DIR/versions/<version>/"
  say "  activate        $INSTALL_DIR/current -> versions/<version>  (previous kept for rollback)"
  say "  command shim    $BIN_DIR/agentgate -> $INSTALL_DIR/current/bin/agentgate"
  case ":$PATH:" in *":$BIN_DIR:"*) ;; *) say "  PATH            $BIN_DIR is not on your PATH (you'd be told how to add it)" ;; esac
  if [ "$RUN_SETUP" = 1 ]; then
    if [ -f "$INSTALL_DIR/server/server.json" ] && [ -L "$INSTALL_DIR/current" ]; then say "  then            agentgate update --restart   (existing install; restarts the server if no agent session runs)"
    else say "  then            agentgate setup   (starts the local server as a launchd agent, prints the pairing QR)"; fi
  else
    say "  then            nothing (--no-setup)"
  fi
  say "  sudo            never"
  exit 0
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/agentgate-install.XXXXXX")"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT INT TERM HUP

fetch() { # url dest
  case "$1" in
    https://*) curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$2" "$1" ;;
    *) curl -fsSL --retry 3 -o "$2" "$1" ;;
  esac
}

say "${B}Installing AgentGate${N} ${D}($TARGET)${N}"
fetch "$ASSETS/SHA256SUMS" "$TMP/SHA256SUMS" || die "could not download $ASSETS/SHA256SUMS"
LINE="$(grep -E "^[0-9a-f]{64}  agentgate-[0-9A-Za-z.-]+-$TARGET\.tar\.gz\$" "$TMP/SHA256SUMS" || true)"
[ -n "$LINE" ] && [ "$(printf '%s\n' "$LINE" | wc -l | tr -d ' ')" = 1 ] || die "the release has no (unique) build for $TARGET"
SUM="${LINE%%  *}"
FILE="${LINE#*  }"
REL="${FILE#agentgate-}"
REL="${REL%-$TARGET.tar.gz}"
printf '%s' "$REL" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.]*)?$' || die "unexpected release file name: $FILE"
[ "$VERSION" = latest ] || [ "$VERSION" = "$REL" ] || die "asked for $VERSION but the release lists $REL"

# ── signature (optional here; mandatory for `agentgate update`) ──────────────
find_openssl() {
  for c in openssl /opt/homebrew/bin/openssl /usr/local/bin/openssl /opt/homebrew/opt/openssl@3/bin/openssl /usr/local/opt/openssl@3/bin/openssl; do
    p="$(command -v "$c" 2>/dev/null || true)"
    [ -n "$p" ] && [ -x "$p" ] || continue
    case "$("$p" version 2>/dev/null)" in "OpenSSL "[3-9]*) printf '%s' "$p"; return 0 ;; esac
  done
  return 1
}
SIG_STATE="not checked"
case "$RELEASE_PUBKEY_PEM" in
  *"-----BEGIN PUBLIC KEY-----"*)
    if OPENSSL="$(find_openssl)"; then
      fetch "$ASSETS/SHA256SUMS.sig" "$TMP/SHA256SUMS.sig" || die "release signature (SHA256SUMS.sig) is missing"
      printf '%s\n' "$RELEASE_PUBKEY_PEM" >"$TMP/release.pub.pem"
      printf 'agentgate-release:v1\n' >"$TMP/signed-message"
      cat "$TMP/SHA256SUMS" >>"$TMP/signed-message"
      SIG_B64="$(tr -d ' \n\r' <"$TMP/SHA256SUMS.sig" | tr -- '-_' '+/')"
      [ "${#SIG_B64}" = 86 ] || die "malformed release signature"
      printf '%s==' "$SIG_B64" | "$OPENSSL" base64 -d -A >"$TMP/sig.bin" 2>/dev/null || die "malformed release signature"
      "$OPENSSL" pkeyutl -verify -pubin -inkey "$TMP/release.pub.pem" -rawin -in "$TMP/signed-message" -sigfile "$TMP/sig.bin" >/dev/null 2>&1 ||
        die "release signature verification FAILED — not installing"
      SIG_STATE="verified"
    else
      SIG_STATE="not checked (no OpenSSL 3 found; install it with 'brew install openssl@3' to check it)"
    fi
    ;;
  *) SIG_STATE="not checked (this installer copy has no embedded release key)" ;;
esac
if [ "$SIG_STATE" != verified ] && [ "$REQUIRE_SIG" = 1 ]; then die "signature $SIG_STATE — refusing (AGENTGATE_REQUIRE_SIGNATURE=1)"; fi

# ── download + checksum ─────────────────────────────────────────────────────
say "${D}downloading $FILE${N}"
fetch "$ASSETS/$FILE" "$TMP/$FILE" || die "could not download $ASSETS/$FILE"
GOT="$(shasum -a 256 "$TMP/$FILE" | awk '{print $1}')"
[ "$GOT" = "$SUM" ] || die "checksum mismatch for $FILE (expected $SUM, got $GOT) — not installing"
ok "agentgate $REL downloaded — checksum verified, signature $SIG_STATE"

# ── extract into versions/<version> ─────────────────────────────────────────
umask 022
mkdir -p "$INSTALL_DIR/versions"
chmod 700 "$INSTALL_DIR"
INCOMING="$INSTALL_DIR/versions/.incoming-$$"
rm -rf "$INCOMING"
mkdir "$INCOMING"
tar -xzf "$TMP/$FILE" -C "$INCOMING" || die "could not extract $FILE"
for f in bin/agentgate bin/agentgate-hook.sh libexec/node lib/agentgate.mjs lib/api.mjs VERSION; do
  [ -f "$INCOMING/$f" ] || { rm -rf "$INCOMING"; die "release is missing $f"; }
done
[ "$(cat "$INCOMING/VERSION")" = "$REL" ] || { rm -rf "$INCOMING"; die "release VERSION does not match $REL"; }
if [ -n "$(find "$INCOMING" -type l -print 2>/dev/null | head -n 1)" ]; then rm -rf "$INCOMING"; die "release contains symlinks — refusing"; fi
DEST="$INSTALL_DIR/versions/$REL"
if [ -e "$DEST" ]; then
  mv "$DEST" "$INSTALL_DIR/versions/.replaced-$$"
  mv "$INCOMING" "$DEST"
  rm -rf "$INSTALL_DIR/versions/.replaced-$$"
else
  mv "$INCOMING" "$DEST"
fi

# ── activate: flip `current` atomically (rename(2)), remember `previous` ─────
OLD=""
if [ -L "$INSTALL_DIR/current" ]; then OLD="$(readlink "$INSTALL_DIR/current" || true)"; fi
env -i "$DEST/libexec/node" -e '
  const fs = require("fs");
  const [home, rel, old] = process.argv.slice(1);
  const link = (name, target) => {
    const tmp = `${home}/${name}.tmp-${process.pid}`;
    fs.rmSync(tmp, { force: true });
    fs.symlinkSync(target, tmp);
    fs.renameSync(tmp, `${home}/${name}`);
  };
  if (old && old !== `versions/${rel}` && /^versions\/[0-9A-Za-z.-]+$/.test(old)) link("previous", old);
  link("current", `versions/${rel}`);
' "$INSTALL_DIR" "$REL" "$OLD" || die "could not activate $REL"
ok "installed $DEST ${D}(current → versions/$REL)${N}"

# ── command shim on PATH ────────────────────────────────────────────────────
SHIM="$BIN_DIR/agentgate"
mkdir -p "$BIN_DIR"
if [ -e "$SHIM" ] && ! grep -q "$SHIM_MARKER" "$SHIM" 2>/dev/null; then
  warn "$SHIM exists and was not written by this installer — leaving it alone"
  warn "use $INSTALL_DIR/current/bin/agentgate directly, or remove $SHIM and re-run"
else
  cat >"$SHIM.tmp.$$" <<EOF
#!/bin/sh
$SHIM_MARKER (written by the AgentGate installer; \`agentgate uninstall\` removes it)
exec '$INSTALL_DIR/current/bin/agentgate' "\$@"
EOF
  chmod 755 "$SHIM.tmp.$$"
  mv -f "$SHIM.tmp.$$" "$SHIM"
  ok "command: $SHIM"
fi
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *)
    warn "$BIN_DIR is not on your PATH. Add it (zsh):"
    say "    echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> ~/.zprofile && export PATH=\"$BIN_DIR:\$PATH\""
    ;;
esac

AG="$INSTALL_DIR/current/bin/agentgate"
"$AG" update --prune >/dev/null 2>&1 || true

# ── setup ───────────────────────────────────────────────────────────────────
if [ "$RUN_SETUP" = 0 ]; then
  say ""
  say "Next: ${B}agentgate setup${N}   (starts the local server and prints the pairing QR)"
  exit 0
fi
if [ -f "$INSTALL_DIR/server/server.json" ] && [ -n "$OLD" ]; then
  say ""
  "$AG" update --restart || warn "could not restart the server — run: agentgate restart"
  ok "AgentGate $REL is ready. Pair another phone with: agentgate pair"
  exit 0
fi
say ""
exec "$AG" setup
