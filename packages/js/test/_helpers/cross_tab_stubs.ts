/**
 * Test stubs for cross-tab APIs that jsdom does not implement.
 *
 * - {@link installFifoLocks} replaces `navigator.locks` with a strict-FIFO
 *   in-process implementation. Concurrent `request()` calls run their
 *   callbacks one after another, in the order they were submitted.
 * - {@link installInProcessBroadcastChannel} replaces the global
 *   `BroadcastChannel` constructor with an in-memory bus shared across
 *   all instances created within the same test.
 *
 * Each installer returns an `uninstall()` that restores the prior state.
 * Tests should call the installer in `beforeEach` and the uninstall in
 * `afterEach` to keep cross-test isolation.
 */

interface LockManagerLike {
  request<T>(name: string, callback: (lock: unknown) => Promise<T>): Promise<T>;
}

/**
 * Install a strict-FIFO `navigator.locks` stub.
 *
 * Returns an uninstall function. If `navigator.locks` was set, it's
 * restored; otherwise the property is deleted (mirroring jsdom's
 * baseline where `navigator.locks` is undefined).
 */
export function installFifoLocks(): () => void {
  const navWithLocks = navigator as unknown as { locks?: LockManagerLike };
  const had = "locks" in navWithLocks;
  const prior = navWithLocks.locks;

  // One queue per lock name; each entry is the previous tail's promise.
  // A new request chains onto the current tail and becomes the new tail.
  const queues = new Map<string, Promise<unknown>>();

  const fakeLocks: LockManagerLike = {
    async request<T>(
      name: string,
      callback: (lock: unknown) => Promise<T>,
    ): Promise<T> {
      const head = queues.get(name) ?? Promise.resolve();
      // Chain: wait for `head` to resolve, then run our callback.
      const ours = head.then(() => callback({}));
      // Tail swallows errors so a thrown callback doesn't break the queue.
      const tail = ours.catch(() => undefined);
      queues.set(name, tail);
      try {
        return await ours;
      } finally {
        // If we're still the tail, clear the entry so the queue doesn't
        // pin a settled promise across tests.
        if (queues.get(name) === tail) queues.delete(name);
      }
    },
  };

  Object.defineProperty(navigator, "locks", {
    value: fakeLocks,
    writable: true,
    configurable: true,
  });

  return () => {
    if (had) {
      Object.defineProperty(navigator, "locks", {
        value: prior,
        writable: true,
        configurable: true,
      });
    } else {
      delete (navigator as unknown as { locks?: LockManagerLike }).locks;
    }
  };
}

interface BroadcastChannelLike {
  readonly name: string;
  onmessage: ((ev: { data: unknown }) => void) | null;
  postMessage(data: unknown): void;
  close(): void;
}

interface BCConstructor {
  new (name: string): BroadcastChannelLike;
}

/**
 * Install an in-process `BroadcastChannel` constructor.
 *
 * Messages posted on a given channel name are delivered (asynchronously
 * on a microtask) to every other live instance with that name. The
 * poster does not receive its own message (matching the spec).
 */
export function installInProcessBroadcastChannel(): () => void {
  const g = globalThis as unknown as { BroadcastChannel?: BCConstructor };
  const had = "BroadcastChannel" in g;
  const prior = g.BroadcastChannel;

  const subscribers = new Map<string, Set<BroadcastChannelLike>>();

  class FakeBroadcastChannel implements BroadcastChannelLike {
    onmessage: ((ev: { data: unknown }) => void) | null = null;
    private closed = false;
    constructor(public readonly name: string) {
      let set = subscribers.get(name);
      if (!set) {
        set = new Set();
        subscribers.set(name, set);
      }
      set.add(this);
    }
    postMessage(data: unknown): void {
      if (this.closed) return;
      const set = subscribers.get(this.name);
      if (!set) return;
      queueMicrotask(() => {
        for (const sub of set) {
          if (sub === this) continue;
          if (typeof sub.onmessage === "function") {
            sub.onmessage({ data });
          }
        }
      });
    }
    close(): void {
      this.closed = true;
      const set = subscribers.get(this.name);
      set?.delete(this);
      if (set && set.size === 0) subscribers.delete(this.name);
    }
  }

  Object.defineProperty(g, "BroadcastChannel", {
    value: FakeBroadcastChannel,
    writable: true,
    configurable: true,
  });

  return () => {
    if (had) {
      Object.defineProperty(g, "BroadcastChannel", {
        value: prior,
        writable: true,
        configurable: true,
      });
    } else {
      delete (g as { BroadcastChannel?: BCConstructor }).BroadcastChannel;
    }
    subscribers.clear();
  };
}
