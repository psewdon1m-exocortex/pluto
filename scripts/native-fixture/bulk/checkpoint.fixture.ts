import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import { timingSafeEqual } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import type { FastifyInstance } from "fastify";
import { activeFixture } from "./stage3-chat-a.fixture.js";
import { resumeCompletionFixture, type RetainedClient } from "./completion-resume.fixture.js";

type Fixture = Awaited<ReturnType<typeof activeFixture>>;
type Request = {
  schema: string; case: string; requestID: string;
  base: string; state: string; source: string; config: string; ca: string;
  nativeBackupDirectory: string; nativeArchiveSHA256: string; nativeBeforeSHA256: string;
  nativeChildStarted: false;
};
type Proof = {
  schema: string; status: string; requestID: string; graphSHA256: string;
  postgreSQLRestored: boolean; fullSQLRowsCompared: boolean;
  physicalSFTPRestored: boolean; allPhysicalBytesCompared: boolean;
  actualProductReadback: boolean; authorityConfigRestored: boolean;
  originalBackendStoppedReceipt: boolean; originalBackendResumed: boolean;
  canaryBytes: number; nativeArchiveSHA256: string;
};
export function registerBulkCheckpoint(app: FastifyInstance, options: {
  output: string; fixtures: Fixture[]; clients: () => RetainedClient[];
  pauseRetention: () => Promise<void>; rootsChanged: () => void; resumeRetention: () => void;
}) {
  const tokenFile = process.env.BULK_CHECKPOINT_TOKEN_FILE;
  assert(tokenFile && path.isAbsolute(tokenFile), "explicit private checkpoint credential required");
  let phase: "RUNNING" | "CLOSING" | "WAITING_RESTORE" | "RESUMING" | "FAILED" = "RUNNING";
  let used = false;
  const active = new Set<string>();
  app.addHook("onRequest", async (request, reply) => {
    if (request.url === "/__completion/checkpoint") return;
    if (phase !== "RUNNING") return reply.code(503).send({ code: "owned_checkpoint_frozen" });
    active.add(request.id);
  });
  app.addHook("onResponse", async request => { active.delete(request.id); });
  app.addHook("onRequestAbort", async request => { active.delete(request.id); });
  app.post<{ Body: Request }>("/__completion/checkpoint", async (request, reply) => {
    const info = await fs.lstat(tokenFile);
    assert(info.isFile() && !info.isSymbolicLink() && info.size <= 65, "bounded real checkpoint credential");
    const expected = (await fs.readFile(tokenFile, "utf8")).trim();
    const raw = request.headers["x-bulk-checkpoint-token"];
    if (typeof raw !== "string" || !/^[a-f0-9]{64}$/.test(raw) || !/^[a-f0-9]{64}$/.test(expected)
        || !timingSafeEqual(Buffer.from(raw), Buffer.from(expected))) return reply.code(403).send({ code: "owned_checkpoint_credential_required" });
    assert(!used && phase === "RUNNING" && active.size === 0, "one quiet pre-start checkpoint, no active HTTP operation");
    const body = request.body;
    assert(body?.schema === "pluto.native-bulk-checkpoint-request.v1"
      && body.case === "TestCompletionNativeBulkReadbackPauseRestartNoCopies"
      && /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/.test(body.requestID)
      && body.nativeChildStarted === false, "exact original native bulk request");
    assert(path.posix.isAbsolute(body.base) && body.base.startsWith("/retained/") && path.posix.normalize(body.base) === body.base);
    for (const key of ["state", "source", "config", "ca"] as const) {
      const relative = path.posix.relative(body.base, body[key]);
      assert(relative && !relative.startsWith("../") && !path.posix.isAbsolute(relative) && path.posix.normalize(body[key]) === body[key], "exact current original native roots");
    }
    assert(body.nativeBackupDirectory.startsWith("/checkpoint/") && path.posix.normalize(body.nativeBackupDirectory) === body.nativeBackupDirectory);
    assert(/^[a-f0-9]{64}$/.test(body.nativeArchiveSHA256) && /^[a-f0-9]{64}$/.test(body.nativeBeforeSHA256));
    used = true; phase = "CLOSING";
    try {
      await options.pauseRetention();
      assert.equal(active.size, 0);
      // Actual executor.close persists STOPPED only after backend work joins.
      // No SQL owner field or queue is patched by this coordination route.
      for (const fixture of options.fixtures) await fixture.close();
      phase = "WAITING_RESTORE";
      const envelope = { schema: "saturn.native-bulk-checkpoint-closed.v1", at: new Date().toISOString(), request: body,
        httpRequestsJoined: true, actualFixtureCloseReturned: true, retentionJoined: true, pendingHTTP: active.size,
        roots: options.clients().map(c => ({ kind: c.kind, databaseName: c.databaseName, rootId: c.binding.root_id, backendIdentity: c.backendIdentity })) };
      const marker = await fs.open(path.join(options.output, "bulk-checkpoint-request.json"), "wx", 0o600);
      try { await marker.writeFile(JSON.stringify(envelope, null, 2) + "\n"); await marker.sync(); } finally { await marker.close(); }
      const directory = await fs.open(options.output, "r"); try { await directory.sync(); } finally { await directory.close(); }
      const receipt = path.join(options.output, "bulk-checkpoint-restored.json"), deadline = Date.now() + 420000;
      let proof: Proof | undefined;
      while (Date.now() < deadline) {
        const file = await fs.lstat(receipt).catch((error: NodeJS.ErrnoException) => { if (error.code !== "ENOENT") throw error; return undefined; });
        if (file) {
          assert(file.isFile() && !file.isSymbolicLink() && file.size > 0 && file.size <= 1048576);
          proof = JSON.parse(await fs.readFile(receipt, "utf8")) as Proof; break;
        }
        if (reply.raw.destroyed) throw Error("native caller left checkpoint; original admission stays closed");
        await delay(100);
      }
      assert(proof && proof.schema === "pluto.native-bulk-checkpoint-proof.v1" && proof.status === "PASS_GENUINE_FULL_GRAPH_RESTORE"
        && proof.requestID === body.requestID && proof.nativeArchiveSHA256 === body.nativeArchiveSHA256
        && /^[a-f0-9]{64}$/.test(proof.graphSHA256) && proof.postgreSQLRestored && proof.fullSQLRowsCompared
        && proof.physicalSFTPRestored && proof.allPhysicalBytesCompared && proof.actualProductReadback
        && proof.authorityConfigRestored && proof.originalBackendStoppedReceipt && !proof.originalBackendResumed
        && Number.isSafeInteger(proof.canaryBytes) && proof.canaryBytes > 0,
      "complete actual restored graph required before resuming original backend");
      phase = "RESUMING";
      const clients = options.clients();
      assert.equal(clients.length, options.fixtures.length);
      for (let index = 0; index < clients.length; index++) {
        const client = clients[index]; assert(client);
        // This API validates the genuine STOPPED receipt and original generation,
        // keys, SQL roles and bindings before the supported executor start.
        const fixture = await resumeCompletionFixture(client);
        try {
        const rows = await fixture.admin.withSql(sql => sql<{ backend_identity: string; generation: string; state: string }[]>`SELECT backend_identity,generation,state FROM sync_backend_executor WHERE backend_identity=${client.backendIdentity}`);
        assert.equal(rows.length, 1); const row = rows[0]; assert(row);
        assert.equal(row.backend_identity, fixture.backendIdentity); assert.equal(row.generation, fixture.generation); assert.equal(row.state, "RUNNING");
        options.fixtures[index] = fixture;
        } catch (error) {
          try { await fixture.close(); } catch (closeError) { throw new AggregateError([error, closeError], "resumed fixture validation and normal close failed"); }
          throw error;
        }
      }
      options.rootsChanged(); options.resumeRetention();
      phase = "RUNNING";
      const completed = { ...proof, originalBackendResumed: true, originalResumedAt: new Date().toISOString(), activeHTTPAtResume: active.size };
      const output = await fs.open(path.join(options.output, "bulk-checkpoint-complete.json"), "wx", 0o600);
      try { await output.writeFile(JSON.stringify(completed, null, 2) + "\n"); await output.sync(); } finally { await output.close(); }
      return completed;
    } catch (error) {
      const failedPhase = phase; phase = "FAILED";
      const failure = { schema: "saturn.native-bulk-checkpoint-failed.v1", at: new Date().toISOString(), requestID: body.requestID, failedPhase,
        name: error instanceof Error ? error.name : "UnknownError", message: error instanceof Error ? error.message : String(error), stack: error instanceof Error ? error.stack : undefined };
      const failed = await fs.open(path.join(options.output, "bulk-checkpoint-failed.json"), "wx", 0o600);
      try { await failed.writeFile(JSON.stringify(failure, null, 2) + String.fromCharCode(10)); await failed.sync(); } finally { await failed.close(); }
      // The explicit failed state does not silently reopen original admission.
      throw error;
    }
  });
}
