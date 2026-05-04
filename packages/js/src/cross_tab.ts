/**
 * Cross-tab refresh coalescing.
 *
 * Two tabs that hit `getAccessToken` simultaneously with stale tokens
 * would each `POST /oauth/token` with the same refresh token; one wins
 * and the other gets `invalid_grant` because the refresh rotated. This
 * module serializes the refreshes so only one POST fires per
 * (tab-cluster, refresh-window).
 *
 * Two paths:
 *
 * 1. **Web Locks** (Chrome 69+, Firefox 96+, Safari 15.4+) — primary.
 *    `navigator.locks.request("allowthem:refresh", cb)` serializes
 *    callbacks across tabs. Inside the lock we re-read storage; if
 *    another tab already refreshed and we observe its tokens (only
 *    possible with cross-tab storage adapters), we return early.
 *
 * 2. **BroadcastChannel** (Firefox 38+) — fallback for older Firefox.
 *    Leader-election protocol: every tab posts a 128-bit nonce; highest
 *    nonce wins. Loser waits up to 5s for a `"refreshed"` message,
 *    then falls back to its own refresh.
 *
 * Storage observability matters: with the default per-tab memory store,
 * the lock-then-storage-observe trick can't surface the winner's fresh
 * tokens to the loser. The loser's POST then fails with
 * `invalid_grant`, which `onTokenExpired` (h6d.2 Step 6) converts into
 * a graceful logout. Cross-tab storage adapters (h6d.2 Step 8) eliminate
 * this race entirely.
 */

import type { TokenSet, TokenStore } from "./tokens.js";

interface LockManagerLike {
  request<T>(name: string, callback: (lock: unknown) => Promise<T>): Promise<T>;
}

const LOCK_NAME = "allowthem:refresh";
const CHANNEL_NAME = "allowthem:refresh";
const ELECTION_WAIT_MS = 50;
const LEADER_DEATH_TIMEOUT_MS = 5000;

interface RefreshArgs {
  store: TokenStore;
  expirySkewMs: number;
  refreshOnce: () => Promise<TokenSet>;
}

/**
 * Coalesce a refresh across tabs. Inner `refreshOnce` is the SDK's
 * in-tab single-flight (h6d.1) and is wrapped by the cross-tab gate
 * here so concurrent tabs don't both POST.
 */
export async function refreshAcrossTabs(args: RefreshArgs): Promise<TokenSet> {
  const navWithLocks = navigator as unknown as { locks?: LockManagerLike };
  if (typeof navWithLocks.locks?.request === "function") {
    return webLocksPath(navWithLocks.locks, args);
  }
  if (typeof BroadcastChannel === "function") {
    return broadcastChannelPath(args);
  }
  // Neither API: degrade to single-tab inner single-flight.
  return args.refreshOnce();
}

async function webLocksPath(
  locks: LockManagerLike,
  args: RefreshArgs,
): Promise<TokenSet> {
  return locks.request(LOCK_NAME, async () => {
    // Inside the lock another tab may have just rotated tokens *and*
    // (with a cross-tab storage adapter) we may already see them.
    const cur = args.store.get();
    if (cur && Date.now() < cur.expiresAt - args.expirySkewMs) {
      return cur;
    }
    return args.refreshOnce();
  });
}

interface ClaimMessage {
  type: "claim";
  nonce: string;
  ts: number;
}

interface RefreshedMessage {
  type: "refreshed";
}

type ChannelMessage = ClaimMessage | RefreshedMessage;

async function broadcastChannelPath(args: RefreshArgs): Promise<TokenSet> {
  const ch = new BroadcastChannel(CHANNEL_NAME);
  try {
    const myNonce = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
    const myTs = Date.now();
    const claims: ClaimMessage[] = [{ type: "claim", nonce: myNonce, ts: myTs }];

    let resolveRefreshed!: (v: TokenSet | null) => void;
    const refreshedSignal = new Promise<TokenSet | null>((resolve) => {
      resolveRefreshed = resolve;
    });

    ch.onmessage = (e: { data: unknown }) => {
      const msg = e.data as ChannelMessage;
      if (msg?.type === "claim") {
        claims.push(msg);
      } else if (msg?.type === "refreshed") {
        const fresh = args.store.get();
        if (fresh && Date.now() < fresh.expiresAt - args.expirySkewMs) {
          resolveRefreshed(fresh);
        } else {
          resolveRefreshed(null);
        }
      }
    };

    ch.postMessage({ type: "claim", nonce: myNonce, ts: myTs } as ClaimMessage);

    await sleep(ELECTION_WAIT_MS);

    // Highest nonce wins. Tiebreak on lower ts (older claim), then nonce
    // ASCII order — collisions at 128 bits are negligible but still
    // deterministic.
    const leader = claims.slice().sort((a, b) => {
      if (a.nonce !== b.nonce) return b.nonce.localeCompare(a.nonce);
      if (a.ts !== b.ts) return a.ts - b.ts;
      return a.nonce.localeCompare(b.nonce);
    })[0]!;

    if (leader.nonce === myNonce) {
      const tokens = await args.refreshOnce();
      ch.postMessage({ type: "refreshed" } as RefreshedMessage);
      return tokens;
    }

    // Loser path: wait for "refreshed" message; if leader dies, fall
    // through to our own refresh.
    const deadline = sleep(LEADER_DEATH_TIMEOUT_MS).then(() => null);
    const fresh = await Promise.race([refreshedSignal, deadline]);
    if (fresh) return fresh;
    return args.refreshOnce();
  } finally {
    ch.close();
  }
}

function bytesToHex(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i]!;
    s += b.toString(16).padStart(2, "0");
  }
  return s;
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
