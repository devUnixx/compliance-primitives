/**
 * Entry point — wires config, DB, and Indexer together and runs the
 * poll loop until SIGINT/SIGTERM.
 *
 * Optional health-check server
 * ────────────────────────────
 * Set HEALTH_PORT (e.g. HEALTH_PORT=8080) to start a minimal HTTP server
 * alongside the indexer. It exposes:
 *
 *   GET /health  — 200 OK after the first successful poll, 503 before that
 *   GET /status  — JSON with lastIndexedLedger and lastPollAt
 */

import { loadConfig } from "./config.js";
import { ComplianceDb } from "./db.js";
import { HealthServer } from "./health.js";
import { Indexer } from "./indexer.js";

async function main(): Promise<void> {
  const config = loadConfig();
  const db = await ComplianceDb.open(config.dbPath);

  // Start the health/metrics HTTP server if HEALTH_PORT is configured.
  let health: HealthServer | undefined;
  const healthPortRaw = process.env.HEALTH_PORT?.trim();
  if (healthPortRaw) {
    const port = Number(healthPortRaw);
    if (!Number.isInteger(port) || port <= 0 || port > 65535) {
      throw new Error(`Invalid HEALTH_PORT: ${healthPortRaw} — must be a TCP port number (1–65535)`);
    }
    health = new HealthServer(db, { port });
    health.start();
  }

  const indexer = new Indexer(config, db, health);

  function shutdown(signal: string): void {
    console.log(`\nReceived ${signal}, shutting down…`);
    indexer.stop();
    health?.stop();
    db.close();
    process.exit(0);
  }

  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));

  indexer.start();
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
