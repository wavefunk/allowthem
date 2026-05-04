import { describe, it, expect, afterEach } from "vitest";
import {
  installFifoLocks,
  installInProcessBroadcastChannel,
} from "./cross_tab_stubs.js";

let uninstall: (() => void) | null = null;

afterEach(() => {
  uninstall?.();
  uninstall = null;
});

describe("installFifoLocks", () => {
  it("runs concurrent requests sequentially in FIFO order", async () => {
    uninstall = installFifoLocks();

    const order: number[] = [];
    const results = await Promise.all([
      navigator.locks!.request("k", async () => {
        await new Promise<void>((r) => setTimeout(r, 5));
        order.push(1);
        return "a";
      }),
      navigator.locks!.request("k", async () => {
        order.push(2);
        return "b";
      }),
      navigator.locks!.request("k", async () => {
        order.push(3);
        return "c";
      }),
    ]);

    expect(order).toEqual([1, 2, 3]);
    expect(results).toEqual(["a", "b", "c"]);
  });

  it("recovers from a thrown callback (next caller still runs)", async () => {
    uninstall = installFifoLocks();
    await expect(
      navigator.locks!.request("k", async () => {
        throw new Error("boom");
      }),
    ).rejects.toThrow("boom");

    const v = await navigator.locks!.request("k", async () => 42);
    expect(v).toBe(42);
  });

  it("uninstall removes the stub", () => {
    uninstall = installFifoLocks();
    expect(navigator.locks).toBeDefined();
    uninstall();
    uninstall = null;
    expect((navigator as { locks?: unknown }).locks).toBeUndefined();
  });

  it("different lock names do not block each other", async () => {
    uninstall = installFifoLocks();
    let aDone = false;
    const slow = navigator.locks!.request("a", async () => {
      await new Promise<void>((r) => setTimeout(r, 20));
      aDone = true;
      return "a";
    });
    const fast = await navigator.locks!.request("b", async () => "b");
    expect(fast).toBe("b");
    expect(aDone).toBe(false);
    await slow;
  });
});

describe("installInProcessBroadcastChannel", () => {
  it("delivers messages from one instance to another with the same name", async () => {
    uninstall = installInProcessBroadcastChannel();
    const a = new BroadcastChannel("k");
    const b = new BroadcastChannel("k");

    const received = new Promise<unknown>((resolve) => {
      b.onmessage = (e) => resolve(e.data);
    });

    a.postMessage({ hello: "world" });
    expect(await received).toEqual({ hello: "world" });
    a.close();
    b.close();
  });

  it("does not deliver back to the poster", async () => {
    uninstall = installInProcessBroadcastChannel();
    const a = new BroadcastChannel("k");
    let aGot = false;
    a.onmessage = () => {
      aGot = true;
    };
    a.postMessage("hi");
    await new Promise<void>((r) => setTimeout(r, 0));
    expect(aGot).toBe(false);
    a.close();
  });

  it("does not cross channel names", async () => {
    uninstall = installInProcessBroadcastChannel();
    const a = new BroadcastChannel("a");
    const b = new BroadcastChannel("b");
    let bGot = false;
    b.onmessage = () => {
      bGot = true;
    };
    a.postMessage("nope");
    await new Promise<void>((r) => setTimeout(r, 0));
    expect(bGot).toBe(false);
    a.close();
    b.close();
  });

  it("close stops further deliveries to that instance", async () => {
    uninstall = installInProcessBroadcastChannel();
    const a = new BroadcastChannel("k");
    const b = new BroadcastChannel("k");
    let count = 0;
    b.onmessage = () => {
      count += 1;
    };
    a.postMessage("1");
    await new Promise<void>((r) => setTimeout(r, 0));
    b.close();
    a.postMessage("2");
    await new Promise<void>((r) => setTimeout(r, 0));
    expect(count).toBe(1);
    a.close();
  });

  it("uninstall restores the prior global (or removes the stub if absent)", () => {
    const priorHad = "BroadcastChannel" in globalThis;
    const prior = (globalThis as { BroadcastChannel?: unknown }).BroadcastChannel;
    uninstall = installInProcessBroadcastChannel();
    // Stub is in place — different from prior (if any).
    expect(typeof BroadcastChannel).toBe("function");
    uninstall();
    uninstall = null;
    if (priorHad) {
      expect(
        (globalThis as { BroadcastChannel?: unknown }).BroadcastChannel,
      ).toBe(prior);
    } else {
      expect(
        (globalThis as { BroadcastChannel?: unknown }).BroadcastChannel,
      ).toBeUndefined();
    }
  });
});
