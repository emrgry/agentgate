import { describe, expect, it } from "vitest";
import { canonicalJson } from "../src/index.ts";

describe("canonicalJson", () => {
  it("produces identical output regardless of key insertion order", () => {
    expect(canonicalJson({ b: 1, a: 2, c: 3 })).toBe(canonicalJson({ c: 3, a: 2, b: 1 }));
  });

  it("sorts keys and emits no whitespace", () => {
    expect(canonicalJson({ b: 1, a: "x" })).toBe('{"a":"x","b":1}');
  });

  it("sorts keys of nested objects at every depth", () => {
    const a = { outer: { z: 1, y: { q: true, p: null } }, first: [{ k2: 2, k1: 1 }] };
    const b = { first: [{ k1: 1, k2: 2 }], outer: { y: { p: null, q: true }, z: 1 } };
    expect(canonicalJson(a)).toBe(canonicalJson(b));
    expect(canonicalJson(a)).toBe('{"first":[{"k1":1,"k2":2}],"outer":{"y":{"p":null,"q":true},"z":1}}');
  });

  it("sorts keys by UTF-16 code units (uppercase before lowercase)", () => {
    expect(canonicalJson({ b: 1, B: 2, a: 3, _: 4 })).toBe('{"B":2,"_":4,"a":3,"b":1}');
  });

  it("drops undefined object members", () => {
    expect(canonicalJson({ a: 1, b: undefined })).toBe('{"a":1}');
    expect(canonicalJson({ a: 1, b: undefined })).toBe(canonicalJson({ a: 1 }));
  });

  it("encodes undefined array elements as null", () => {
    expect(canonicalJson([1, undefined, 3])).toBe("[1,null,3]");
  });

  it("preserves array order (arrays are not sorted)", () => {
    expect(canonicalJson([3, 1, 2])).toBe("[3,1,2]");
    expect(canonicalJson([1, 2])).not.toBe(canonicalJson([2, 1]));
  });

  it("serializes primitives", () => {
    expect(canonicalJson(null)).toBe("null");
    expect(canonicalJson(true)).toBe("true");
    expect(canonicalJson(false)).toBe("false");
    expect(canonicalJson(0)).toBe("0");
    expect(canonicalJson(-1.5)).toBe("-1.5");
    expect(canonicalJson("s")).toBe('"s"');
    expect(canonicalJson({})).toBe("{}");
    expect(canonicalJson([])).toBe("[]");
  });

  it.each([NaN, Infinity, -Infinity])("rejects non-finite number %s", (n) => {
    expect(() => canonicalJson(n)).toThrow(TypeError);
    expect(() => canonicalJson({ a: n })).toThrow(TypeError);
    expect(() => canonicalJson([n])).toThrow(TypeError);
  });

  it.each([
    ["bigint", 1n],
    ["function", () => 1],
    ["symbol", Symbol("x")],
  ])("rejects unsupported type %s", (_name, v) => {
    expect(() => canonicalJson(v)).toThrow(TypeError);
  });

  it("rejects top-level undefined (no JSON representation)", () => {
    expect(() => canonicalJson(undefined)).toThrow(TypeError);
  });

  it("round-trips unicode, emoji and escapes through JSON.parse", () => {
    const value = { "clé": "héllo wörld", emoji: "🚀", cjk: "日本語", ctrl: "a\nb\t\"c\"\\", nul: "\u0000" };
    const out = canonicalJson(value);
    expect(JSON.parse(out)).toEqual(value);
  });

  it("distinguishes visually similar unicode strings (no normalization)", () => {
    // "é" precomposed vs "e" + combining acute: different bytes, different meaning to a shell.
    expect(canonicalJson({ a: "é" })).not.toBe(canonicalJson({ a: "é" }));
  });

  it("is deterministic across repeated calls", () => {
    const v = { x: [1, { b: 2, a: 1 }], y: "z" };
    expect(canonicalJson(v)).toBe(canonicalJson(structuredClone(v)));
  });
});
