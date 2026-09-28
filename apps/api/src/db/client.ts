import { mkdirSync } from "node:fs";
import type { PgDatabase, PgQueryResultHKT } from "drizzle-orm/pg-core";
import { schema } from "./schema.ts";
import { bootstrapSchema } from "./bootstrap.ts";

/**
 * Driver-agnostic database handle. Both drizzle-orm/pglite and drizzle-orm/node-postgres
 * databases (and their transactions) are PgDatabase instances, so services only see this.
 */
export type Db = PgDatabase<PgQueryResultHKT, typeof schema>;

export type DatabaseTarget =
  | { kind: "postgres"; url: string }
  | { kind: "pglite"; dataDir: string }
  | { kind: "memory" };

export interface Database {
  db: Db;
  driver: "postgres" | "pglite";
  close(): Promise<void>;
}

export async function openDatabase(target: DatabaseTarget): Promise<Database> {
  let database: Database;
  if (target.kind === "postgres") {
    const { default: pg } = await import("pg");
    const { drizzle } = await import("drizzle-orm/node-postgres");
    const pool = new pg.Pool({ connectionString: target.url, max: 10 });
    database = {
      db: drizzle(pool, { schema }) as unknown as Db,
      driver: "postgres",
      close: () => pool.end(),
    };
  } else {
    const { PGlite } = await import("@electric-sql/pglite");
    const { drizzle } = await import("drizzle-orm/pglite");
    let client;
    if (target.kind === "pglite") {
      mkdirSync(target.dataDir, { recursive: true });
      client = new PGlite(target.dataDir);
    } else {
      client = new PGlite();
    }
    await client.waitReady;
    database = {
      db: drizzle(client, { schema }) as unknown as Db,
      driver: "pglite",
      close: () => client.close(),
    };
  }
  await bootstrapSchema(database.db);
  return database;
}
