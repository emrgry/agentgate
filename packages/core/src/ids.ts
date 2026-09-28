import { randomBytes } from "node:crypto";

export type IdPrefix = "usr" | "dev" | "agt" | "ses" | "act" | "apr" | "aud";

/** Prefixed, URL-safe, 128-bit random ids, e.g. "apr_3kT9...". */
export function newId(prefix: IdPrefix): string {
  return `${prefix}_${randomBytes(16).toString("base64url")}`;
}
