/**
 * Lifecycle event emitter for `@allowthem/js`.
 *
 * Synchronous in-process pub/sub. The client closure instantiates one
 * {@link EventEmitter} and exposes its `on` method; subscribers register
 * handlers and receive events as the SDK transitions between states.
 *
 * Throwing handlers do not prevent subsequent handlers from running —
 * the SDK can't trust user code to behave, but it won't let one bad
 * subscriber take down the rest.
 */

import type { UserClaims } from "./types.js";

export type EventName = "login" | "logout" | "token_refreshed" | "error";

export interface EventPayloads {
  login: { user: UserClaims };
  logout: { reason: "user" | "expired" | "error" };
  token_refreshed: { expiresAt: number };
  error: { code: string; description?: string };
}

export type EventHandler<E extends EventName> = (
  payload: EventPayloads[E],
) => void;

/**
 * Synchronous in-process emitter. One instance per client.
 */
export class EventEmitter {
  // We accept `EventHandler<EventName>` storage and re-narrow at emit time.
  // The public `on`/`emit` methods preserve the per-event payload type.
  private readonly handlers = new Map<
    EventName,
    Set<EventHandler<EventName>>
  >();

  /**
   * Subscribe to an event. Returns an unsubscribe function.
   */
  on<E extends EventName>(event: E, handler: EventHandler<E>): () => void {
    let set = this.handlers.get(event);
    if (!set) {
      set = new Set();
      this.handlers.set(event, set);
    }
    // Cast safe: we only emit `EventPayloads[E]` for `event === E`.
    const stored = handler as EventHandler<EventName>;
    set.add(stored);
    return () => {
      set!.delete(stored);
    };
  }

  /**
   * Fire `event` with `payload`. Synchronous; handlers run in
   * registration order.
   */
  emit<E extends EventName>(event: E, payload: EventPayloads[E]): void {
    const set = this.handlers.get(event);
    if (!set) return;
    for (const h of set) {
      try {
        (h as EventHandler<E>)(payload);
      } catch (err) {
        // Defensive: a thrown handler must not block subsequent handlers.
        // Use console.error so the throw is visible in dev.
        // eslint-disable-next-line no-console
        console.error(
          `[allowthem] event handler for "${event}" threw:`,
          err,
        );
      }
    }
  }
}
