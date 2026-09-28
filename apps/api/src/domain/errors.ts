/** Domain failure mapped 1:1 to `{ error: { code, message } }` by the HTTP layer. */
export class DomainError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    /** Extra top-level fields merged into the error response (e.g. the current approval). */
    readonly extra?: Record<string, unknown>,
  ) {
    super(message);
    this.name = "DomainError";
  }
}

export const notFound = (what: string) => new DomainError(404, "not_found", `${what} not found`);
export const forbidden = (message: string) => new DomainError(403, "forbidden", message);
export const conflict = (code: string, message: string, extra?: Record<string, unknown>) =>
  new DomainError(409, code, message, extra);
export const badRequest = (code: string, message: string) => new DomainError(400, code, message);
