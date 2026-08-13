import { connect, type Socket, type TcpNetConnectOpts } from "node:net";
import {
  EventSocketDuplex,
  type EventSocketDuplexOptions,
} from "./io/event-socket-duplex.ts";

export type NodeSocketDuplexOptions = EventSocketDuplexOptions;

/** ByteDuplex adapter for Node.js TCP sockets (also supported by Bun). */
export class NodeSocketDuplex extends EventSocketDuplex {
  constructor(socket: Socket, options: NodeSocketDuplexOptions = {}) {
    super(socket, options);
  }
}

export async function connectNodeTcp(
  options: TcpNetConnectOpts,
  duplexOptions?: NodeSocketDuplexOptions,
  signal?: AbortSignal,
): Promise<NodeSocketDuplex> {
  if (signal?.aborted) {
    throw signal.reason instanceof Error
      ? signal.reason
      : new Error("connect aborted");
  }
  return new Promise<NodeSocketDuplex>((resolve, reject) => {
    const socket = connect(options);
    const onConnect = () => {
      signal?.removeEventListener("abort", onAbort);
      socket.off("error", onError);
      try {
        resolve(new NodeSocketDuplex(socket, duplexOptions));
      } catch (error) {
        socket.destroy();
        reject(error);
      }
    };
    const onAbort = () => {
      socket.off("error", onError);
      socket.off("connect", onConnect);
      socket.destroy();
      reject(
        signal?.reason instanceof Error
          ? signal.reason
          : new Error("connect aborted"),
      );
    };
    const onError = (error: Error) => {
      signal?.removeEventListener("abort", onAbort);
      socket.off("connect", onConnect);
      socket.destroy();
      reject(error);
    };
    signal?.addEventListener("abort", onAbort, { once: true });
    socket.once("error", onError);
    socket.once("connect", onConnect);
  });
}

export type { TcpNetConnectOpts };
export {
  EventSocketDuplex,
  type EventSocket,
  type EventSocketDuplexOptions,
} from "./io/event-socket-duplex.ts";
