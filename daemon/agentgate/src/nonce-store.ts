import { closeSync, mkdirSync, openSync, readdirSync, readFileSync, unlinkSync, writeSync } from "node:fs";
import { join } from "node:path";
import type { NonceStore } from "@agentgate/core";

const NONCE_RE = /^[A-Za-z0-9_-]{16,128}$/;

/**
 * Persistent single-use nonce registry: one file per consumed nonce.
 *
 * Atomicity comes from `open(O_CREAT|O_EXCL)` ("wx"): exactly one process can create
 * a given file, so the check-and-set is atomic even across concurrent agentgate
 * processes of the same user. Consumed nonces are kept until their token expiry
 * (after which the token is rejected as expired anyway) and then pruned.
 *
 * Any I/O error → return false (treated as "replayed" by the verifier → fail closed).
 */
export class FileNonceStore implements NonceStore {
  constructor(private readonly dir: string) {}

  consume(nonce: string, expiresAt: Date): boolean {
    if (!NONCE_RE.test(nonce)) return false; // also prevents path traversal
    try {
      mkdirSync(this.dir, { recursive: true, mode: 0o700 });
      this.prune();
      const fd = openSync(join(this.dir, nonce), "wx", 0o600);
      try {
        writeSync(fd, `${expiresAt.toISOString()}\n`);
      } finally {
        closeSync(fd);
      }
      return true;
    } catch {
      // EEXIST → replay. Anything else → cannot guarantee single use → refuse.
      return false;
    }
  }

  has(nonce: string): boolean {
    if (!NONCE_RE.test(nonce)) return false;
    try {
      readFileSync(join(this.dir, nonce));
      return true;
    } catch {
      return false;
    }
  }

  /** Remove nonces whose token expired more than an hour ago. Best effort. */
  private prune(now = Date.now()): void {
    let names: string[];
    try {
      names = readdirSync(this.dir);
    } catch {
      return;
    }
    for (const name of names) {
      if (!NONCE_RE.test(name)) continue;
      try {
        const exp = Date.parse(readFileSync(join(this.dir, name), "utf8").trim());
        if (Number.isFinite(exp) && exp + 3_600_000 < now) unlinkSync(join(this.dir, name));
      } catch {
        /* ignore */
      }
    }
  }
}
