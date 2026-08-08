/**
 * Minimal byte-stream duplex injected by the host runtime.
 *
 * `read(n)` may return between 1 and n bytes. It returns an empty array only
 * after EOF. The protocol buffers fragmented reads internally.
 */
export interface ByteDuplex {
  read(n: number): Promise<Uint8Array>;
  write(bytes: Uint8Array): Promise<void>;
  close(): Promise<void>;
}

/** In-memory paired duplexes for tests (left ↔ right). */
export function pairedByteDuplexes(): [ByteDuplex, ByteDuplex] {
  type Side = {
    inbox: Uint8Array[];
    closed: boolean;
    peerClosed: boolean;
    waiter?: { n: number; resolve: (bytes: Uint8Array) => void };
  };
  const leftState: Side = { inbox: [], closed: false, peerClosed: false };
  const rightState: Side = { inbox: [], closed: false, peerClosed: false };

  const take = (state: Side, n: number): Uint8Array | undefined => {
    const chunk = state.inbox[0];
    if (!chunk) return undefined;
    if (chunk.length <= n) {
      state.inbox.shift();
      return chunk;
    }
    const result = chunk.slice(0, n);
    state.inbox[0] = chunk.slice(n);
    return result;
  };

  const wake = (state: Side): void => {
    const waiter = state.waiter;
    if (!waiter) return;
    if (state.closed) {
      state.waiter = undefined;
      waiter.resolve(new Uint8Array(0));
      return;
    }
    const chunk = take(state, waiter.n);
    if (chunk) {
      state.waiter = undefined;
      waiter.resolve(chunk);
    } else if (state.peerClosed) {
      state.waiter = undefined;
      waiter.resolve(new Uint8Array(0));
    }
  };

  const make = (state: Side, peer: Side): ByteDuplex => ({
    read(n) {
      if (state.closed) return Promise.resolve(new Uint8Array(0));
      const chunk = take(state, n);
      if (chunk) return Promise.resolve(chunk);
      if (state.peerClosed) return Promise.resolve(new Uint8Array(0));
      if (state.waiter) return Promise.reject(new Error("concurrent reads are not supported"));
      return new Promise<Uint8Array>((resolve) => {
        state.waiter = { n, resolve };
      });
    },
    async write(bytes) {
      if (state.closed || peer.closed) throw new Error("cannot write to closed duplex");
      peer.inbox.push(bytes.slice());
      wake(peer);
    },
    async close() {
      if (state.closed) return;
      state.closed = true;
      wake(state);
      peer.peerClosed = true;
      wake(peer);
    },
  });

  const left = make(leftState, rightState);
  const right = make(rightState, leftState);
  return [left, right];
}
