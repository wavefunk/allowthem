import * as fs from "fs";
import * as http from "http";
import * as os from "os";
import * as path from "path";
import { spawnSync, spawn } from "child_process";

const workspaceRoot = path.resolve(__dirname, "../..");
const dbPath = path.resolve(__dirname, "test-e2e.db");
const pidFile = path.join(os.tmpdir(), "allowthem-e2e.pid");

function getBinaryPath(): string {
  // Use cargo metadata to find the actual target directory (may be outside the workspace)
  const result = spawnSync(
    "cargo",
    ["metadata", "--no-deps", "--format-version", "1"],
    { cwd: workspaceRoot, encoding: "utf8" }
  );
  if (result.status !== 0) {
    throw new Error("cargo metadata failed");
  }
  const meta = JSON.parse(result.stdout);
  return path.join(meta.target_directory, "debug", "allowthem");
}

async function pollHealth(timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const ready = await new Promise<boolean>((resolve) => {
      const req = http.get("http://127.0.0.1:3100/health", (res) => {
        resolve(res.statusCode === 200);
      });
      req.on("error", () => resolve(false));
      req.setTimeout(500, () => {
        req.destroy();
        resolve(false);
      });
    });
    if (ready) return;
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error("Server did not start in time");
}

export default async function globalSetup(): Promise<void> {
  console.log("[e2e] Building allowthem binary...");
  const build = spawnSync("cargo", ["build", "-p", "allowthem"], {
    cwd: workspaceRoot,
    stdio: "inherit",
  });
  if (build.status !== 0) {
    throw new Error("cargo build failed");
  }

  const binaryPath = getBinaryPath();
  console.log(`[e2e] Starting allowthem server at ${binaryPath} on port 3100...`);
  const server = spawn(binaryPath, [], {
    cwd: workspaceRoot,
    env: {
      ...process.env,
      ALLOWTHEM_BIND: "127.0.0.1:3100",
      ALLOWTHEM_DATABASE_URL: `sqlite:${dbPath}?mode=rwc`,
      ALLOWTHEM_COOKIE_SECURE: "false",
      ALLOWTHEM_BASE_URL: "http://127.0.0.1:3100",
      ALLOWTHEM_SIGNING_KEY_HEX:
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
      ALLOWTHEM_IS_PRODUCTION: "false",
      ALLOWTHEM_MAX_LOGIN_ATTEMPTS: "50",
    },
    stdio: "pipe",
    detached: false,
  });

  const logPath = path.resolve(__dirname, "server.log");
  const logFile = fs.createWriteStream(logPath, { flags: "w" });
  server.stderr?.on("data", (d) => {
    process.stderr.write(d);
    logFile.write(d);
  });

  fs.writeFileSync(pidFile, String(server.pid));
  console.log(`[e2e] Server PID ${server.pid} written to ${pidFile}`);

  console.log("[e2e] Waiting for server health check...");
  try {
    await pollHealth(30_000);
  } catch (err) {
    server.kill("SIGTERM");
    throw err;
  }
  console.log("[e2e] Server is ready.");
}
