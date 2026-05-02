/**
 * Proactive refresh timer.
 *
 * When `proactiveRefresh: true` is set on the client config, the SDK
 * schedules a `setTimeout` after every successful `store.put` to
 * refresh the token in the background `expirySkewSeconds` before
 * `expiresAt`. Long-idle tabs never wake up to a 401.
 *
 * The timer is best-effort: browsers throttle `setTimeout` in hidden
 * tabs (some down to 1 minute resolution after a few minutes of
 * background). The on-demand refresh in `getAccessToken` is the
 * authoritative path; this timer is only an optimization for
 * dashboards / kiosks / presentations.
 */

export class ProactiveTimer {
  private handle: ReturnType<typeof setTimeout> | null = null;

  /**
   * Schedule `fn` to run after `ms` (or 1 second floor). Cancels any
   * previously scheduled timer first.
   */
  schedule(ms: number, fn: () => void): void {
    this.cancel();
    const safeMs = Math.max(1000, ms);
    this.handle = setTimeout(fn, safeMs);
  }

  /**
   * Cancel a pending refresh. Safe to call multiple times.
   */
  cancel(): void {
    if (this.handle !== null) {
      clearTimeout(this.handle);
      this.handle = null;
    }
  }
}
