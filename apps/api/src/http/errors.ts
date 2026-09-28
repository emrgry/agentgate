import type { FastifyError, FastifyInstance } from "fastify";
import { ZodError } from "zod";
import { ApprovalTransitionError } from "@agentgate/core";
import { DomainError } from "../domain/errors.ts";

/** Maps every failure to `{ error: { code, message } }`. */
export function registerErrorHandling(app: FastifyInstance): void {
  app.setErrorHandler((err: FastifyError | Error, req, reply) => {
    if (err instanceof DomainError) {
      return reply.status(err.status).send({ error: { code: err.code, message: err.message }, ...err.extra });
    }
    if (err instanceof ZodError) {
      const message = err.issues
        .slice(0, 5)
        .map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`)
        .join("; ");
      return reply.status(400).send({ error: { code: "validation_error", message } });
    }
    if (err instanceof ApprovalTransitionError) {
      return reply.status(409).send({ error: { code: "invalid_transition", message: err.message } });
    }
    const status = (err as FastifyError).statusCode;
    if (typeof status === "number" && status >= 400 && status < 500) {
      const code = ((err as FastifyError).code ?? "bad_request").toLowerCase();
      return reply.status(status).send({ error: { code, message: err.message } });
    }
    req.log.error({ err }, "unhandled error");
    return reply.status(500).send({ error: { code: "internal_error", message: "internal server error" } });
  });

  app.setNotFoundHandler((req, reply) => {
    reply.status(404).send({ error: { code: "not_found", message: `route ${req.method} ${req.url.split("?")[0]} not found` } });
  });
}
