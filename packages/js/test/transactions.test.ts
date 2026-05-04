import { describe, it, expect, beforeEach } from "vitest";
import {
  popTransaction,
  storeTransaction,
  sweepStaleTransactions,
  type TxnRecord,
} from "../src/transactions.js";

const KEY = "allowthem:txn";

function record(now = Date.now()): TxnRecord {
  return {
    codeVerifier: "v",
    nonce: "n",
    redirectUri: "https://app.example/callback",
    scope: "openid profile",
    appState: { from: "/x" },
    createdAt: now,
  };
}

describe("transactions", () => {
  beforeEach(() => {
    sessionStorage.clear();
  });

  it("stores and pops a transaction once", () => {
    storeTransaction("s1", record());
    const popped = popTransaction("s1");
    expect(popped).not.toBeNull();
    expect(popped?.codeVerifier).toBe("v");

    // Second pop returns null (transaction is single-use).
    expect(popTransaction("s1")).toBeNull();
  });

  it("returns null for unknown state", () => {
    expect(popTransaction("never-stored")).toBeNull();
  });

  it("drops records older than 10 minutes on read", () => {
    const old = Date.now() - 11 * 60 * 1000;
    storeTransaction("stale", record(old), old);
    // Read at "now" (which is far past old + TTL): popped is null.
    expect(popTransaction("stale")).toBeNull();
  });

  it("preserves fresh records during sweep", () => {
    storeTransaction("a", record());
    storeTransaction("b", record());
    sweepStaleTransactions();
    expect(popTransaction("a")).not.toBeNull();
    expect(popTransaction("b")).not.toBeNull();
  });

  it("removes the storage key when the map becomes empty", () => {
    storeTransaction("only", record());
    expect(sessionStorage.getItem(KEY)).not.toBeNull();
    popTransaction("only");
    expect(sessionStorage.getItem(KEY)).toBeNull();
  });

  it("appState round-trips unchanged", () => {
    const state = { deeply: { nested: ["a", 1, true] } };
    storeTransaction("s", { ...record(), appState: state });
    expect(popTransaction("s")?.appState).toEqual(state);
  });

  it("ignores corrupted JSON in sessionStorage", () => {
    sessionStorage.setItem(KEY, "not json");
    // Should not throw; treats as empty map.
    expect(popTransaction("any")).toBeNull();
    sessionStorage.setItem(KEY, "null");
    expect(popTransaction("any")).toBeNull();
  });
});
