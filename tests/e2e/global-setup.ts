import * as fs from "fs";
import * as http from "http";
import * as os from "os";
import * as path from "path";
import { spawnSync, spawn } from "child_process";

const workspaceRoot = path.resolve(__dirname, "../..");
const dbPath = path.resolve(__dirname, "test-e2e.db");
// Hoisted to ensure byte-identical DB URL for both the server env var and
// the seed binary's --db-url flag; a mismatch (e.g. sqlite: vs sqlite://)
// would open a different handle and the spec would navigate to a server
// with no seeded app.
const dbUrl = `sqlite:${dbPath}?mode=rwc`;
const pidFile = path.join(os.tmpdir(), "allowthem-e2e.pid");
const seededClientIdFile = path.resolve(__dirname, ".seeded-client-id");

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
      ALLOWTHEM_DATABASE_URL: dbUrl,
      ALLOWTHEM_COOKIE_SECURE: "false",
      ALLOWTHEM_BASE_URL: "http://127.0.0.1:3100",
      ALLOWTHEM_SIGNING_KEY_HEX:
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
      ALLOWTHEM_CSRF_KEY_HEX:
        "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe",
      ALLOWTHEM_IS_PRODUCTION: "false",
      ALLOWTHEM_MAX_LOGIN_ATTEMPTS: "50",
      ALLOWTHEM_OAUTH_MOCK: "true",
      ALLOWTHEM_MFA_KEY_HEX:
        "4242424242424242424242424242424242424242424242424242424242424242",
      ALLOWTHEM_BOOTSTRAP_ADMIN_EMAIL: "admin@e2e.test",
      ALLOWTHEM_BOOTSTRAP_ADMIN_PASSWORD: "AdminE2E1234!",
      ALLOWTHEM_BOOTSTRAP_OIDC_APP_NAME: "E2E Test App",
      ALLOWTHEM_BOOTSTRAP_OIDC_REDIRECT_URI:
        "http://127.0.0.1:3100/test-callback",
      ALLOWTHEM_BOOTSTRAP_OIDC_CLIENT_ID: "e2e-test-client",
      ALLOWTHEM_BOOTSTRAP_OIDC_CLIENT_SECRET: "e2e-test-secret-1234",
    },
    stdio: "pipe",
    detached: false,
  });

  const logPath = path.resolve(__dirname, "server.log");
  const logFile = fs.createWriteStream(logPath, { flags: "w" });
  // tracing_subscriber::fmt() writes to stdout by default; tee both streams to server.log
  server.stdout?.on("data", (d) => {
    process.stderr.write(d);
    logFile.write(d);
  });
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

  // Seed a branded application via the `seed-branding` Rust binary. We
  // cannot write directly to the SQLite DB from TS (branding schema drift
  // would silently break the spec); the Rust binary shares the same crate
  // as the server, so a schema mismatch is a compile error instead.
  console.log("[e2e] Seeding branded application via seed-branding...");
  const seedBuild = spawnSync("cargo", ["build", "--bin", "seed-branding"], {
    cwd: workspaceRoot,
    stdio: "inherit",
  });
  if (seedBuild.status !== 0) {
    server.kill("SIGTERM");
    throw new Error("cargo build --bin seed-branding failed");
  }
  const seedArgs = [
    "run",
    "--quiet",
    "--bin",
    "seed-branding",
    "--",
    "--db-url",
    dbUrl,
    "--name",
    "m5-accent-fixture",
    "--accent-hex",
    "#cba6f7",
    "--ink",
    "black",
    "--redirect-uri",
    "http://localhost:3000/callback",
  ];
  console.log(`[e2e] cargo ${seedArgs.join(" ")}`);
  const seedResult = spawnSync("cargo", seedArgs, {
    cwd: workspaceRoot,
    encoding: "utf8",
  });
  if (seedResult.status !== 0) {
    console.error(seedResult.stderr);
    server.kill("SIGTERM");
    throw new Error("seed-branding binary failed");
  }
  const seededClientId = seedResult.stdout.trim();
  if (!seededClientId) {
    server.kill("SIGTERM");
    throw new Error("seed-branding produced empty client_id on stdout");
  }
  fs.writeFileSync(seededClientIdFile, seededClientId);
  console.log(`[e2e] Seeded client_id=${seededClientId} written to ${seededClientIdFile}`);
}
