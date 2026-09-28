/**
 * @agentgate/signing/node: Node-only bridges between Node's PEM Ed25519 keys (the
 * server identity key is PKCS#8 / SPKI PEM today) and this package's raw keys.
 * Never import this from the React Native app.
 */
import { createPrivateKey, createPublicKey } from "node:crypto";
import { base64urlDecode, base64urlEncode } from "./encoding.ts";
import { publicKeyFromPrivateKey } from "./index.ts";

function assertEd25519(k: { asymmetricKeyType?: string }): void {
  if (k.asymmetricKeyType !== "ed25519") throw new TypeError(`expected an Ed25519 key, got ${k.asymmetricKeyType ?? "unknown"}`);
}

/**
 * Raw public key (base64url, 43 chars) from a PEM. Accepts an SPKI public key PEM or a
 * PKCS#8 private key PEM (the public key is derived).
 */
export function publicKeyFromNodePem(pem: string): string {
  const key = createPublicKey(pem);
  assertEd25519(key);
  const jwk = key.export({ format: "jwk" }) as { x?: string };
  if (!jwk.x) throw new TypeError("publicKeyFromNodePem: no public key material");
  return jwk.x;
}

/** SPKI PEM for a raw base64url Ed25519 public key (for node:crypto.verify). */
export function rawPublicKeyToNodeSpkiPem(publicKeyB64url: string): string {
  const raw = base64urlDecode(publicKeyB64url);
  if (!raw || raw.length !== 32) throw new TypeError("rawPublicKeyToNodeSpkiPem: expected a base64url raw 32-byte key");
  const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: base64urlEncode(raw) }, format: "jwk" });
  return key.export({ type: "spki", format: "pem" }).toString();
}

/** Raw 32-byte secret key (seed) from a PKCS#8 Ed25519 private key PEM, e.g. for signServerHello. */
export function privateKeyFromNodePem(pem: string): Uint8Array {
  const key = createPrivateKey(pem);
  assertEd25519(key);
  const jwk = key.export({ format: "jwk" }) as { d?: string };
  const seed = jwk.d ? base64urlDecode(jwk.d) : null;
  if (!seed || seed.length !== 32) throw new TypeError("privateKeyFromNodePem: no Ed25519 seed");
  return seed;
}

/** PKCS#8 PEM for a raw 32-byte secret key (so node:crypto.sign can use a noble-generated key). */
export function rawPrivateKeyToNodePkcs8Pem(privateKey: Uint8Array): string {
  const x = publicKeyFromPrivateKey(privateKey);
  const key = createPrivateKey({
    key: { kty: "OKP", crv: "Ed25519", d: base64urlEncode(privateKey), x },
    format: "jwk",
  });
  return key.export({ type: "pkcs8", format: "pem" }).toString();
}
