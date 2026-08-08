import { SHORT_ID_TO_COMMAND, SHORT_MESSAGE_IDS } from "./ids.ts";
import {
  decodeAddr,
  decodeAddrV2,
  decodeBlock,
  decodeGetHeaders,
  decodeHeaders,
  decodeInventory,
  decodeTransaction,
  decodeVersion,
  encodeAddr,
  encodeAddrV2,
  encodeBlock,
  encodeGetHeaders,
  encodeHeaders,
  encodeInventory,
  encodeTransaction,
  encodeVersion,
  type AddrPayload,
  type AddrV2Payload,
  type BlockPayload,
  type GetHeadersPayload,
  type HeadersPayload,
  type InventoryPayload,
  type Transaction,
  type VersionPayload,
} from "./payloads.ts";

export type WireMessageType =
  | { kind: "short"; id: number }
  | { kind: "long"; command: string };

export type Message =
  | { command: "version"; payload: VersionPayload }
  | { command: "verack" }
  | { command: "ping"; nonce: Uint8Array }
  | { command: "pong"; nonce: Uint8Array }
  | { command: "getaddr" }
  | { command: "getheaders"; payload: GetHeadersPayload }
  | { command: "headers"; payload: HeadersPayload }
  | { command: "getdata"; payload: InventoryPayload }
  | { command: "inv"; payload: InventoryPayload }
  | { command: "notfound"; payload: InventoryPayload }
  | { command: "block"; payload: BlockPayload }
  | { command: "tx"; payload: Transaction }
  | { command: "addr"; payload: AddrPayload }
  | { command: "addrv2"; payload: AddrV2Payload }
  | { command: "opaque"; type: WireMessageType; payload: Uint8Array };

function encodeLongCommand(command: string): Uint8Array {
  if (command.length === 0 || command.length > 12) {
    throw new Error(`command length must be in [1, 12], got ${command.length}`);
  }
  for (let i = 0; i < command.length; i++) {
    const code = command.charCodeAt(i);
    if (code < 0x20 || code > 0x7e) {
      throw new Error("command must contain printable ASCII only");
    }
  }
  const out = new Uint8Array(13);
  for (let i = 0; i < command.length; i++) out[i + 1] = command.charCodeAt(i);
  return out;
}

function encodeCommand(command: string): Uint8Array {
  const shortId = SHORT_MESSAGE_IDS[command];
  if (shortId !== undefined) {
    return new Uint8Array([shortId]);
  }
  return encodeLongCommand(command);
}

function decodeCommand(
  bytes: Uint8Array,
): { command: string | undefined; type: WireMessageType; headerLen: number } {
  if (bytes.length < 1) throw new Error("empty message contents");
  const first = bytes[0]!;
  if (first === 0) {
    if (bytes.length < 13) throw new Error("truncated long command");
    const raw = bytes.subarray(1, 13);
    const nul = raw.indexOf(0);
    const end = nul === -1 ? raw.length : nul;
    if (end === 0) throw new Error("long command must not be empty");
    for (let i = 0; i < end; i++) {
      if (raw[i]! < 0x20 || raw[i]! > 0x7e) {
        throw new Error("long command must contain printable ASCII only");
      }
    }
    for (let i = end; i < raw.length; i++) {
      if (raw[i] !== 0) throw new Error("nonzero byte after long command padding");
    }
    let command = "";
    for (let i = 0; i < end; i++) command += String.fromCharCode(raw[i]!);
    return { command, type: { kind: "long", command }, headerLen: 13 };
  }
  const command = SHORT_ID_TO_COMMAND[first];
  return { command, type: { kind: "short", id: first }, headerLen: 1 };
}

function frame(command: string, payload: Uint8Array): Uint8Array {
  const header = encodeCommand(command);
  const out = new Uint8Array(header.length + payload.length);
  out.set(header);
  out.set(payload, header.length);
  return out;
}

/** Encode application-layer contents (pre-packet encryption). */
export function encodeMessage(msg: Message): Uint8Array {
  if (msg.command === "verack" || msg.command === "getaddr") {
    return encodeCommand(msg.command);
  }
  if (msg.command === "ping") {
    if (msg.nonce.length !== 8) throw new Error("ping nonce must be 8 bytes");
    const hdr = encodeCommand("ping");
    const out = new Uint8Array(hdr.length + 8);
    out.set(hdr, 0);
    out.set(msg.nonce, hdr.length);
    return out;
  }
  if (msg.command === "pong") {
    if (msg.nonce.length !== 8) throw new Error("pong nonce must be 8 bytes");
    const hdr = encodeCommand("pong");
    const out = new Uint8Array(hdr.length + 8);
    out.set(hdr, 0);
    out.set(msg.nonce, hdr.length);
    return out;
  }
  if (msg.command === "opaque") {
    const hdr =
      msg.type.kind === "short"
        ? (() => {
          if (!Number.isInteger(msg.type.id) || msg.type.id < 1 || msg.type.id > 255) {
            throw new Error(`short message ID must be in [1, 255], got ${msg.type.id}`);
          }
          return new Uint8Array([msg.type.id]);
        })()
        : encodeLongCommand(msg.type.command);
    const out = new Uint8Array(hdr.length + msg.payload.length);
    out.set(hdr, 0);
    out.set(msg.payload, hdr.length);
    return out;
  }
  switch (msg.command) {
    case "version":
      return frame(msg.command, encodeVersion(msg.payload));
    case "addr":
      return frame(msg.command, encodeAddr(msg.payload));
    case "addrv2":
      return frame(msg.command, encodeAddrV2(msg.payload));
    case "getheaders":
      return frame(msg.command, encodeGetHeaders(msg.payload));
    case "headers":
      return frame(msg.command, encodeHeaders(msg.payload));
    case "getdata":
    case "inv":
    case "notfound":
      return frame(msg.command, encodeInventory(msg.payload));
    case "block":
      return frame(msg.command, encodeBlock(msg.payload));
    case "tx":
      return frame(msg.command, encodeTransaction(msg.payload));
  }
}

/** Decode application-layer contents after packet decryption. */
export function decodeMessage(contents: Uint8Array): Message {
  const { command, type, headerLen } = decodeCommand(contents);
  const payload = contents.subarray(headerLen);

  switch (command) {
    case "verack":
      if (payload.length !== 0) throw new Error("verack payload must be empty");
      return { command: "verack" };
    case "getaddr":
      if (payload.length !== 0) throw new Error("getaddr payload must be empty");
      return { command: "getaddr" };
    case "ping":
      if (payload.length !== 8) throw new Error("ping payload must be 8 bytes");
      return { command: "ping", nonce: payload };
    case "pong":
      if (payload.length !== 8) throw new Error("pong payload must be 8 bytes");
      return { command: "pong", nonce: payload };
    case "version":
      return { command: "version", payload: decodeVersion(payload) };
    case "getheaders":
      return { command: "getheaders", payload: decodeGetHeaders(payload) };
    case "headers":
      return { command: "headers", payload: decodeHeaders(payload) };
    case "getdata":
      return { command: "getdata", payload: decodeInventory(payload) };
    case "inv":
      return { command: "inv", payload: decodeInventory(payload) };
    case "notfound":
      return { command: "notfound", payload: decodeInventory(payload) };
    case "block":
      return { command: "block", payload: decodeBlock(payload) };
    case "tx":
      return { command: "tx", payload: decodeTransaction(payload) };
    case "addr":
      return { command: "addr", payload: decodeAddr(payload) };
    case "addrv2":
      return { command: "addrv2", payload: decodeAddrV2(payload) };
    default:
      return { command: "opaque", type, payload };
  }
}
