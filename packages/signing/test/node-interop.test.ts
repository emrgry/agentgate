/**
 * noble ↔ node:crypto Ed25519 interop, in both directions, plus the PEM bridges in
 * `@agentgate/signing/node`. Proves the phone (noble) and the daemon (can be Node native)
 * produce and accept byte-identical signatures.
 */
import { createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { DecisionPayloadV2 } from "@agentgate/protocol";
import {
  canonicalJson,
  generateDeviceKeyPair,
  publicKeyFingerprint,
  publicKeyFromPrivateKey,
  signDecision,
  signServerHello,
  verifyDecision,
  verifyServerHello,
} from "../src/index.ts";
import {
  privateKeyFromNodePem,
  publicKeyFromNodePem,
  rawPrivateKeyToNodePkcs8Pem,
  rawPublicKeyToNodeSpkiPem,
} from "../src/node.ts";

const rng = (n: number) => new Uint8Array(randomBytes(n));
const T0 = Date.parse("2026-09-26T12:00:00.000Z");
const HASH = "c".repeat(64);
const payload = (): DecisionPayloadV2 => ({
  v: 2,
  approval_id: "apr_9",
  action_id: "act_9",
  session_id: "ses_9",
  action_hash: HASH,
  decision: "approve",
  device_id: "dev_9",
  issued_at: new Date(T0).toISOString(),
  expires_at: new Date(T0 + 60_000).toISOString(),
  nonce: randomBytes(18).toString("base64url"),
});
const verifyOpts = (publicKey: string) => ({
  publicKeyFor: (id: string) => (id === "dev_9" ? publicKey : null),
  expectedApprovalId: "apr_9",
  expectedActionHash: HASH,
  now: new Date(T0 + 1_000),
  requireDecision: "approve" as const,
});

describe("PEM bridges", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const pubPem = publicKey.export({ type: "spki", format: "pem" }).toString();

  it("publicKeyFromNodePem accepts SPKI and PKCS#8 and agrees with Node's JWK", () => {
    const x = (publicKey.export({ format: "jwk" }) as { x: string }).x;
    expect(publicKeyFromNodePem(pubPem)).toBe(x);
    expect(publicKeyFromNodePem(privPem)).toBe(x);
  });

  it("privateKeyFromNodePem gives the seed whose noble public key matches", () => {
    const seed = privateKeyFromNodePem(privPem);
    expect(seed).toHaveLength(32);
    expect(publicKeyFromPrivateKey(seed)).toBe(publicKeyFromNodePem(pubPem));
  });

  it("rawPublicKeyToNodeSpkiPem / rawPrivateKeyToNodePkcs8Pem round trip", () => {
    const kp = generateDeviceKeyPair(rng);
    const spki = rawPublicKeyToNodeSpkiPem(kp.publicKey);
    expect(spki).toMatch(/^-----BEGIN PUBLIC KEY-----/);
    expect(publicKeyFromNodePem(spki)).toBe(kp.publicKey);
    const pkcs8 = rawPrivateKeyToNodePkcs8Pem(kp.privateKey);
    expect(privateKeyFromNodePem(pkcs8)).toEqual(kp.privateKey);
    expect(rawPublicKeyToNodeSpkiPem(publicKeyFromNodePem(pubPem))).toBe(pubPem);
  });

  it("rejects non-Ed25519 keys and malformed input", () => {
    const rsa = generateKeyPairSync("rsa", { modulusLength: 1024 });
    expect(() => publicKeyFromNodePem(rsa.publicKey.export({ type: "spki", format: "pem" }).toString())).toThrow(/Ed25519/);
    expect(() => privateKeyFromNodePem(rsa.privateKey.export({ type: "pkcs8", format: "pem" }).toString())).toThrow(/Ed25519/);
    expect(() => rawPublicKeyToNodeSpkiPem("short")).toThrow();
    expect(() => publicKeyFromNodePem("not a pem")).toThrow();
  });
});

describe("noble → node: tokens signed by this package verify with node:crypto", () => {
  it("signDecision (noble) → crypto.verify (node)", () => {
    const kp = generateDeviceKeyPair(rng);
    const token = signDecision(payload(), kp.privateKey);
    const [, body, sig] = token.split(".") as [string, string, string];
    const nodeKey = createPublicKey(rawPublicKeyToNodeSpkiPem(kp.publicKey));
    expect(verify(null, Buffer.from(body, "ascii"), nodeKey, Buffer.from(sig, "base64url"))).toBe(true);
    // and the signature is byte-identical to Node's own (Ed25519 is deterministic)
    const nodePriv = createPrivateKey(rawPrivateKeyToNodePkcs8Pem(kp.privateKey));
    expect(sign(null, Buffer.from(body, "ascii"), nodePriv).toString("base64url")).toBe(sig);
  });

  it("signServerHello (noble) → crypto.verify (node)", () => {
    const kp = generateDeviceKeyPair(rng);
    const challenge = randomBytes(32).toString("base64url");
    const sig = signServerHello(challenge, kp.privateKey);
    const msg = Buffer.from(`agentgate-pairing-hello:v1:${challenge}`, "utf8");
    expect(verify(null, msg, createPublicKey(rawPublicKeyToNodeSpkiPem(kp.publicKey)), Buffer.from(sig, "base64url"))).toBe(true);
  });

  it("many random messages agree", () => {
    for (let i = 0; i < 25; i++) {
      const kp = generateDeviceKeyPair(rng);
      const p = { ...payload(), approval_id: `apr_${i}`, nonce: randomBytes(20).toString("base64url") };
      const [, body, sig] = signDecision(p, kp.privateKey).split(".") as [string, string, string];
      expect(verify(null, Buffer.from(body, "ascii"), createPublicKey(rawPublicKeyToNodeSpkiPem(kp.publicKey)), Buffer.from(sig, "base64url"))).toBe(true);
    }
  });
});

describe("node → noble: tokens signed with node:crypto verify with this package", () => {
  it("crypto.sign (node, PEM identity key) → verifyDecision (noble)", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const body = Buffer.from(canonicalJson(payload()), "utf8").toString("base64url");
    const sig = sign(null, Buffer.from(body, "ascii"), privateKey).toString("base64url");
    const pub = publicKeyFromNodePem(publicKey.export({ type: "spki", format: "pem" }).toString());
    const r = verifyDecision(`v2.${body}.${sig}`, verifyOpts(pub));
    expect(r.ok).toBe(true);
  });

  it("server hello signed by the daemon's Node PEM key verifies on the phone", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const pubPem = publicKey.export({ type: "spki", format: "pem" }).toString();
    const serverPub = publicKeyFromNodePem(pubPem);
    const fp = publicKeyFingerprint(serverPub);
    const challenge = randomBytes(32).toString("base64url");
    // Node-native signature …
    const nodeSig = sign(null, Buffer.from(`agentgate-pairing-hello:v1:${challenge}`, "utf8"), privateKey).toString("base64url");
    expect(verifyServerHello(challenge, nodeSig, serverPub, fp)).toBe(true);
    // … and the same via the PEM bridge + noble, byte-identical.
    const seed = privateKeyFromNodePem(privateKey.export({ type: "pkcs8", format: "pem" }).toString());
    expect(signServerHello(challenge, seed)).toBe(nodeSig);
  });

  it("a Node signature with a flipped bit is rejected by noble", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const body = Buffer.from(canonicalJson(payload()), "utf8").toString("base64url");
    const sig = sign(null, Buffer.from(body, "ascii"), privateKey);
    sig[0] = sig[0]! ^ 0x80;
    const pub = publicKeyFromNodePem(publicKey.export({ type: "spki", format: "pem" }).toString());
    expect(verifyDecision(`v2.${body}.${sig.toString("base64url")}`, verifyOpts(pub))).toEqual({ ok: false, reason: "bad_signature" });
  });

  it("non-canonical S (S + L) is rejected by both noble (strict) and Node", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const body = Buffer.from(canonicalJson(payload()), "utf8").toString("base64url");
    const sig = sign(null, Buffer.from(body, "ascii"), privateKey);
    // Add the group order L to S (little-endian, bytes 32..63): same signature under a lax verifier.
    const L = 2n ** 252n + 27742317777372353535851937790883648493n;
    let s = 0n;
    for (let i = 63; i >= 32; i--) s = (s << 8n) | BigInt(sig[i]!);
    let s2 = s + L;
    if (s2 < 2n ** 256n) {
      const mal = Buffer.from(sig);
      for (let i = 32; i < 64; i++) {
        mal[i] = Number(s2 & 0xffn);
        s2 >>= 8n;
      }
      const pub = publicKeyFromNodePem(publicKey.export({ type: "spki", format: "pem" }).toString());
      expect(verify(null, Buffer.from(body, "ascii"), publicKey, mal)).toBe(false);
      expect(verifyDecision(`v2.${body}.${mal.toString("base64url")}`, verifyOpts(pub))).toEqual({ ok: false, reason: "bad_signature" });
    }
  });
});
