/**
 * Claude API list prices used for MID-TURN cost ESTIMATES (Control Center limits).
 * USD per million tokens. As of 2026-09-27 — an estimate, not a bill: Claude Code's final
 * `total_cost_usd` (turn end) always replaces it. Verify against https://www.anthropic.com/pricing
 * when models change. Unknown models use the most expensive known row (conservative: a limit
 * trips early rather than late).
 */
export const PRICES_AS_OF = "2026-09-27";

export interface ModelPrice {
  input: number;
  output: number;
  /** Cache writes: 1.25× input for the 5-minute TTL, 2× input for the 1-hour TTL (Claude Code uses 1 h). */
  cacheWrite5m: number;
  cacheWrite1h: number;
  cacheRead: number;
}

export const MODEL_PRICES: Array<{ match: RegExp; price: ModelPrice }> = [
  { match: /opus/i, price: { input: 15, output: 75, cacheWrite5m: 18.75, cacheWrite1h: 30, cacheRead: 1.5 } },
  { match: /sonnet/i, price: { input: 3, output: 15, cacheWrite5m: 3.75, cacheWrite1h: 6, cacheRead: 0.3 } },
  { match: /haiku/i, price: { input: 1, output: 5, cacheWrite5m: 1.25, cacheWrite1h: 2, cacheRead: 0.1 } },
];

const CONSERVATIVE = MODEL_PRICES.reduce((a, b) => (b.price.output > a.price.output ? b : a)).price;

export function priceFor(model: string | null | undefined): ModelPrice {
  return (model && MODEL_PRICES.find((p) => p.match.test(model))?.price) || CONSERVATIVE;
}

export interface MessageUsage {
  input_tokens?: number | null;
  output_tokens?: number | null;
  cache_creation_input_tokens?: number | null;
  cache_read_input_tokens?: number | null;
  cache_creation?: { ephemeral_5m_input_tokens?: number | null; ephemeral_1h_input_tokens?: number | null } | null;
}

export function estimateCostUsd(model: string | null | undefined, u: MessageUsage): number {
  const p = priceFor(model);
  const n = (v: number | null | undefined) => (typeof v === "number" && Number.isFinite(v) && v > 0 ? v : 0);
  // Cache writes: split by TTL when reported; otherwise priced at the 1-hour rate (conservative).
  const c = u.cache_creation ?? null;
  const w5 = n(c?.ephemeral_5m_input_tokens);
  const w1 = c ? n(c.ephemeral_1h_input_tokens) : 0;
  const rest = Math.max(0, n(u.cache_creation_input_tokens) - w5 - w1);
  const writes = w5 * p.cacheWrite5m + (w1 + rest) * p.cacheWrite1h;
  return (n(u.input_tokens) * p.input + n(u.output_tokens) * p.output + writes + n(u.cache_read_input_tokens) * p.cacheRead) / 1_000_000;
}
