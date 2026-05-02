import { describe, it, expect, vi } from "vitest";
import { EventEmitter } from "../src/events.js";

describe("EventEmitter", () => {
  it("invokes the handler with the payload on emit", () => {
    const e = new EventEmitter();
    const handler = vi.fn();
    e.on("token_refreshed", handler);
    e.emit("token_refreshed", { expiresAt: 12345 });
    expect(handler).toHaveBeenCalledWith({ expiresAt: 12345 });
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it("returned unsubscribe stops further invocations", () => {
    const e = new EventEmitter();
    const handler = vi.fn();
    const off = e.on("logout", handler);
    e.emit("logout", { reason: "user" });
    off();
    e.emit("logout", { reason: "expired" });
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it("calls multiple handlers for the same event in registration order", () => {
    const e = new EventEmitter();
    const order: number[] = [];
    e.on("token_refreshed", () => order.push(1));
    e.on("token_refreshed", () => order.push(2));
    e.on("token_refreshed", () => order.push(3));
    e.emit("token_refreshed", { expiresAt: 0 });
    expect(order).toEqual([1, 2, 3]);
  });

  it("isolates a throwing handler — subsequent handlers still run", () => {
    const e = new EventEmitter();
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const ok1 = vi.fn();
    const ok2 = vi.fn();
    e.on("error", ok1);
    e.on("error", () => {
      throw new Error("subscriber bug");
    });
    e.on("error", ok2);

    e.emit("error", { code: "x" });
    expect(ok1).toHaveBeenCalled();
    expect(ok2).toHaveBeenCalled();
    expect(errorSpy).toHaveBeenCalled();
    errorSpy.mockRestore();
  });

  it("emit on an event with no handlers is a no-op", () => {
    const e = new EventEmitter();
    expect(() => e.emit("login", { user: { sub: "x" } })).not.toThrow();
  });

  it("the same handler registered twice fires once (Set dedup)", () => {
    const e = new EventEmitter();
    const handler = vi.fn();
    e.on("token_refreshed", handler);
    e.on("token_refreshed", handler);
    e.emit("token_refreshed", { expiresAt: 0 });
    expect(handler).toHaveBeenCalledTimes(1);
  });
});
