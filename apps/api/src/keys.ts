import { createHash, createPrivateKey, createPublicKey, sign as nodeSign } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { generateSigningKeyPair, signApprovalToken } from "@agentgate/core";
import type { ApprovalTokenPayload } from "@agentgate/protocol";

/** Holds the server's Ed25519 approval-signing key. Private key never leaves this object. */
export interface ApprovalSigner {
  readonly kid: string;
  readonly publicKeyPem: string;
  /** Raw 32-byte Ed25519 public key, base64url (local-first contract encoding). */
  readonly publicKeyRaw: string;
  sign(payload: ApprovalTokenPayload): string;
  /** Raw Ed25519 signature (base64url) over arbitrary bytes — server identity proofs. */
  signBytes(data: Uint8Array): string;
}

export function createSigner(privateKeyPem: string): ApprovalSigner {
  const priv = createPrivateKey(privateKeyPem);
  if (priv.asymmetricKeyType !== "ed25519") throw new Error("approval signing key must be Ed25519");
  const pub = createPublicKey(priv);
  const publicKeyPem = pub.export({ type: "spki", format: "pem" }).toString();
  const der = pub.export({ type: "spki", format: "der" });
  const kid = `ed25519-${createHash("sha256").update(der).digest("hex").slice(0, 16)}`;
  return {
    kid,
    publicKeyPem,
    publicKeyRaw: Buffer.from(der.subarray(der.length - 32)).toString("base64url"),
    sign: (payload) => signApprovalToken(payload, privateKeyPem),
    signBytes: (data) => nodeSign(null, data, priv).toString("base64url"),
  };
}

/** Env key wins; otherwise load `<dataDir>/approval-signing-key.pem`, generating it once. */
export function loadSigner(opts: { envPem: string | null; dataDir: string }): ApprovalSigner {
  if (opts.envPem) return createSigner(opts.envPem);
  const file = join(opts.dataDir, "approval-signing-key.pem");
  if (existsSync(file)) return createSigner(readFileSync(file, "utf8"));
  mkdirSync(opts.dataDir, { recursive: true });
  const { privateKeyPem } = generateSigningKeyPair();
  writeFileSync(file, privateKeyPem, { mode: 0o600 });
  return createSigner(privateKeyPem);
}
