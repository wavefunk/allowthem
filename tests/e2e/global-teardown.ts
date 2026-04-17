import * as fs from "fs";
import * as os from "os";
import * as path from "path";

const pidFile = path.join(os.tmpdir(), "allowthem-e2e.pid");
const dbPath = path.resolve(__dirname, "test-e2e.db");

async function waitForExit(pid: number, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      process.kill(pid, 0);
    } catch {
      return; // process is gone
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  // Force kill if still alive
  try {
    process.kill(pid, "SIGKILL");
  } catch {
    // already gone
  }
}

export default async function globalTeardown(): Promise<void> {
  if (!fs.existsSync(pidFile)) {
    console.warn("[e2e] PID file not found — server may not have started");
    return;
  }

  const pid = parseInt(fs.readFileSync(pidFile, "utf8"), 10);
  console.log(`[e2e] Sending SIGTERM to PID ${pid}...`);
  try {
    process.kill(pid, "SIGTERM");
  } catch {
    console.warn(`[e2e] Could not signal PID ${pid} — already stopped?`);
  }

  await waitForExit(pid, 5_000);
  console.log("[e2e] Server stopped.");

  fs.rmSync(pidFile, { force: true });

  for (const suffix of ["", "-wal", "-shm"]) {
    fs.rmSync(dbPath + suffix, { force: true });
  }
  console.log("[e2e] Test database cleaned up.");
}
