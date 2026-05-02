import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { refreshAcrossTabs } from "../src/cross_tab.js";
import type { TokenSet, TokenStore } from "../src/tokens.js";
import {
  installFifoLocks,
  installInProcessBroadcastChannel,
} from "./_helpers/cross_tab_stubs.js";

function makeTokenSet(expiresAt: number): TokenSet {
  return {
    accessToken: "at",
    idToken: "it",
    refreshToken: "rt",
    expiresAt,
  };
}

function sharedStore(): TokenStore {
  let cur: TokenSet | null = null;
  return {
    get: () => (cur ? { ...cur } : null),
    put: (t) => {
      cur = { ...t };
    },
    clear: () => {
      cur = null;
    },
  };
}

let uninstallLocks: (() => void) | null = null;
let uninstallBC: (() => void) | null = null;

afterEach(() => {
  uninstallLocks?.();
  uninstallLocks = null;
  uninstallBC?.();
  uninstallBC = null;
});

describe("refreshAcrossTabs — Web Locks path", () => {
  beforeEach(() => {
    uninstallLocks = installFifoLocks();
  });

  it("calls refreshOnce when no fresh tokens are visible", async () => {
    const store = sharedStore();
    const refreshOnce = vi.fn(async () => makeTokenSet(Date.now() + 3600_000));
    const out = await refreshAcrossTabs({
      store,
      expirySkewMs: 60_000,
      refreshOnce,
    });
    expect(refreshOnce).toHaveBeenCalledTimes(1);
    expect(out.accessToken).toBe("at");
  });

  it("re-reads storage inside the lock and skips refresh when fresh tokens land", async () => {
    // Shared store across both tabs (simulates cross-tab adapter).
    const store = sharedStore();
    let calls = 0;
    const refreshOnce = vi.fn(async () => {
      calls += 1;
      const fresh = makeTokenSet(Date.now() + 3600_000);
      store.put(fresh);
      return fresh;
    });

    // Two concurrent calls; the FIFO lock serializes — second sees the
    // first's stored tokens via shared adapter and returns early.
    const [a, b] = await Promise.all([
      refreshAcrossTabs({ store, expirySkewMs: 60_000, refreshOnce }),
      refreshAcrossTabs({ store, expirySkewMs: 60_000, refreshOnce }),
    ]);
    expect(calls).toBe(1);
    expect(a.accessToken).toBe("at");
    expect(b.accessToken).toBe("at");
  });

  it("with per-tab stores, BOTH still POST (race not eliminated by lock alone)", async () => {
    // Two independent stores → second tab's lock-acquire sees its own
    // stale state, so it POSTs anyway. Documents the spec §1.1 caveat.
    const storeA = sharedStore();
    const storeB = sharedStore();
    const refreshA = vi.fn(async () => makeTokenSet(Date.now() + 3600_000));
    const refreshB = vi.fn(async () => makeTokenSet(Date.now() + 3600_000));
    await Promise.all([
      refreshAcrossTabs({ store: storeA, expirySkewMs: 60_000, refreshOnce: refreshA }),
      refreshAcrossTabs({ store: storeB, expirySkewMs: 60_000, refreshOnce: refreshB }),
    ]);
    expect(refreshA).toHaveBeenCalledTimes(1);
    expect(refreshB).toHaveBeenCalledTimes(1);
  });
});

describe("refreshAcrossTabs — BroadcastChannel fallback path", () => {
  beforeEach(() => {
    // Ensure Web Locks is absent so we hit the BC path.
    Object.defineProperty(navigator, "locks", {
      value: undefined,
      writable: true,
      configurable: true,
    });
    uninstallBC = installInProcessBroadcastChannel();
  });

  it("leader (deterministically pinned) refreshes; loser observes the 'refreshed' message and short-circuits", async () => {
    const store = sharedStore();

    // Pin the leader: first getRandomValues call returns 0xff bytes (max),
    // second returns 0x00 with one bit (min).
    const original = crypto.getRandomValues.bind(crypto);
    let called = 0;
    const spy = vi
      .spyOn(crypto, "getRandomValues")
      .mockImplementation(<T extends ArrayBufferView | null>(buf: T): T => {
        if (buf instanceof Uint8Array) {
          called += 1;
          if (called === 1) buf.fill(0xff);
          else {
            buf.fill(0x00);
            buf[buf.length - 1] = 0x01;
          }
        }
        return buf;
      });

    let refreshes = 0;
    const refreshOnce = async () => {
      refreshes += 1;
      const fresh = makeTokenSet(Date.now() + 3600_000);
      store.put(fresh);
      return fresh;
    };

    const [leader, loser] = await Promise.all([
      refreshAcrossTabs({ store, expirySkewMs: 60_000, refreshOnce }),
      refreshAcrossTabs({ store, expirySkewMs: 60_000, refreshOnce }),
    ]);

    expect(refreshes).toBe(1);
    expect(leader.accessToken).toBe("at");
    expect(loser.accessToken).toBe("at");
    spy.mockRestore();
    // Restore real getRandomValues for any later test
    void original;
  });
});

describe("refreshAcrossTabs — neither API present", () => {
  beforeEach(() => {
    Object.defineProperty(navigator, "locks", {
      value: undefined,
      writable: true,
      configurable: true,
    });
    // Strip BroadcastChannel.
    Object.defineProperty(globalThis, "BroadcastChannel", {
      value: undefined,
      writable: true,
      configurable: true,
    });
  });

  afterEach(() => {
    // Tests after this should get jsdom's BroadcastChannel back. We can't
    // perfectly restore but for our test set leaving it undefined is OK
    // — subsequent tests that need it install via the helper.
  });

  it("calls refreshOnce directly", async () => {
    const store = sharedStore();
    const refreshOnce = vi.fn(async () => makeTokenSet(Date.now() + 3600_000));
    const out = await refreshAcrossTabs({
      store,
      expirySkewMs: 60_000,
      refreshOnce,
    });
    expect(refreshOnce).toHaveBeenCalledTimes(1);
    expect(out.accessToken).toBe("at");
  });
});
