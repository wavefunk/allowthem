/**
 * Pending-login transaction store backed by `sessionStorage`.
 *
 * One entry per `state` parameter. Each entry holds the PKCE
 * `codeVerifier`, the `nonce` (for id_token validation), the
 * `redirectUri` and `scope` actually sent (in case caller-overridden),
 * and the caller's `appState`.
 *
 * Entries older than 10 minutes are dropped on the next read.
 * sessionStorage is per-tab; transactions don't survive tab close.
 */

const KEY = "allowthem:txn";
const TTL_MS = 10 * 60 * 1000;

export interface TxnRecord {
  codeVerifier: string;
  nonce: string;
  redirectUri: string;
  scope: string;
  appState: unknown;
  createdAt: number;
}

interface TxnMap {
  [state: string]: TxnRecord;
}

function read(): TxnMap {
  const raw = sessionStorage.getItem(KEY);
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (parsed && typeof parsed === "object") return parsed as TxnMap;
    return {};
  } catch {
    return {};
  }
}

function write(map: TxnMap): void {
  if (Object.keys(map).length === 0) {
    sessionStorage.removeItem(KEY);
  } else {
    sessionStorage.setItem(KEY, JSON.stringify(map));
  }
}

function sweep(map: TxnMap, now: number): TxnMap {
  const out: TxnMap = {};
  for (const [state, txn] of Object.entries(map)) {
    if (now - txn.createdAt < TTL_MS) out[state] = txn;
  }
  return out;
}

/**
 * Insert a transaction record under `state`. Sweeps stale entries first.
 */
export function storeTransaction(
  state: string,
  txn: TxnRecord,
  now: number = Date.now(),
): void {
  const map = sweep(read(), now);
  map[state] = txn;
  write(map);
}

/**
 * Pop and return the transaction for `state`, or `null` if not found
 * (or stale). Sweeps stale entries on every call.
 */
export function popTransaction(
  state: string,
  now: number = Date.now(),
): TxnRecord | null {
  const map = sweep(read(), now);
  const txn = map[state];
  if (!txn) {
    write(map);
    return null;
  }
  delete map[state];
  write(map);
  return txn;
}

/**
 * Drop expired transactions. Called from `createAllowthemClient` so
 * sessionStorage doesn't accumulate dead entries from cancelled flows.
 */
export function sweepStaleTransactions(now: number = Date.now()): void {
  write(sweep(read(), now));
}
