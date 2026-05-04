import { describe, it, expect, vi } from "vitest";
import { ProactiveTimer } from "../src/proactive.js";

describe("ProactiveTimer", () => {
  it("schedule fires the function after the given delay", () => {
    vi.useFakeTimers();
    try {
      const t = new ProactiveTimer();
      const fn = vi.fn();
      t.schedule(5000, fn);
      expect(fn).not.toHaveBeenCalled();
      vi.advanceTimersByTime(5000);
      expect(fn).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("schedule replaces an existing timer (no double-fire)", () => {
    vi.useFakeTimers();
    try {
      const t = new ProactiveTimer();
      const first = vi.fn();
      const second = vi.fn();
      t.schedule(5000, first);
      t.schedule(2000, second);
      vi.advanceTimersByTime(5000);
      expect(first).not.toHaveBeenCalled();
      expect(second).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("cancel prevents the scheduled function from running", () => {
    vi.useFakeTimers();
    try {
      const t = new ProactiveTimer();
      const fn = vi.fn();
      t.schedule(5000, fn);
      t.cancel();
      vi.advanceTimersByTime(10_000);
      expect(fn).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it("schedule clamps to 1000ms minimum", () => {
    vi.useFakeTimers();
    try {
      const t = new ProactiveTimer();
      const fn = vi.fn();
      t.schedule(0, fn); // should clamp to 1000
      vi.advanceTimersByTime(500);
      expect(fn).not.toHaveBeenCalled();
      vi.advanceTimersByTime(500);
      expect(fn).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("cancel is idempotent (no throw when nothing scheduled)", () => {
    const t = new ProactiveTimer();
    expect(() => t.cancel()).not.toThrow();
    expect(() => t.cancel()).not.toThrow();
  });
});
