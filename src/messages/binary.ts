import { concatBytes } from "../crypto/bytes.ts";
import { bytesToUtf8, utf8ToBytes } from "../crypto/utf8.ts";

const MAX_U64 = 0xffff_ffff_ffff_ffffn;

export class PayloadReader {
  #offset = 0;

  constructor(readonly data: Uint8Array) {}

  get remaining(): number {
    return this.data.length - this.#offset;
  }

  get position(): number {
    return this.#offset;
  }

  peekU8(): number {
    this.#ensure(1);
    return this.data[this.#offset]!;
  }

  u8(): number {
    this.#ensure(1);
    return this.data[this.#offset++]!;
  }

  u16be(): number {
    return this.#view(2).getUint16(0, false);
  }

  u32le(): number {
    return this.#view(4).getUint32(0, true);
  }

  i32le(): number {
    return this.#view(4).getInt32(0, true);
  }

  u64le(): bigint {
    return this.#view(8).getBigUint64(0, true);
  }

  i64le(): bigint {
    return this.#view(8).getBigInt64(0, true);
  }

  bytes(length: number): Uint8Array {
    if (!Number.isSafeInteger(length) || length < 0) {
      throw new RangeError(`invalid byte length: ${length}`);
    }
    this.#ensure(length);
    const result = this.data.slice(this.#offset, this.#offset + length);
    this.#offset += length;
    return result;
  }

  skip(length: number): void {
    if (!Number.isSafeInteger(length) || length < 0) {
      throw new RangeError(`invalid skip length: ${length}`);
    }
    this.#ensure(length);
    this.#offset += length;
  }

  compactSizeBigInt(): bigint {
    const prefix = this.u8();
    if (prefix < 0xfd) return BigInt(prefix);
    if (prefix === 0xfd) {
      const value = BigInt(this.u16le());
      if (value < 0xfdn) throw new Error("non-canonical CompactSize");
      return value;
    }
    if (prefix === 0xfe) {
      const value = BigInt(this.u32le());
      if (value <= 0xffffn) throw new Error("non-canonical CompactSize");
      return value;
    }
    const value = this.u64le();
    if (value <= 0xffff_ffffn) throw new Error("non-canonical CompactSize");
    return value;
  }

  compactSize(max = Number.MAX_SAFE_INTEGER): number {
    const value = this.compactSizeBigInt();
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error("CompactSize exceeds safe integer range");
    }
    const number = Number(value);
    if (number > max) throw new Error(`CompactSize ${number} exceeds limit ${max}`);
    return number;
  }

  varBytes(max = Number.MAX_SAFE_INTEGER): Uint8Array {
    return this.bytes(this.compactSize(max));
  }

  skipVarBytes(max = Number.MAX_SAFE_INTEGER): number {
    const length = this.compactSize(max);
    this.skip(length);
    return length;
  }

  varString(max = Number.MAX_SAFE_INTEGER): string {
    const bytes = this.varBytes(max);
    return bytesToUtf8(bytes);
  }

  finish(): void {
    if (this.remaining !== 0) throw new Error(`${this.remaining} trailing payload bytes`);
  }

  #ensure(length: number): void {
    if (length > this.remaining) {
      throw new Error(`truncated payload: wanted ${length} bytes, have ${this.remaining}`);
    }
  }

  #view(length: number): DataView {
    this.#ensure(length);
    const view = new DataView(this.data.buffer, this.data.byteOffset + this.#offset, length);
    this.#offset += length;
    return view;
  }

  private u16le(): number {
    return this.#view(2).getUint16(0, true);
  }
}

export class PayloadWriter {
  #parts: Uint8Array[] = [];

  u8(value: number): this {
    this.#integer(value, 0xff, "u8");
    this.#parts.push(new Uint8Array([value]));
    return this;
  }

  u16be(value: number): this {
    this.#integer(value, 0xffff, "u16");
    const bytes = new Uint8Array(2);
    new DataView(bytes.buffer).setUint16(0, value, false);
    this.#parts.push(bytes);
    return this;
  }

  u32le(value: number): this {
    this.#integer(value, 0xffff_ffff, "u32");
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, true);
    this.#parts.push(bytes);
    return this;
  }

  i32le(value: number): this {
    if (!Number.isInteger(value) || value < -0x8000_0000 || value > 0x7fff_ffff) {
      throw new RangeError(`invalid i32: ${value}`);
    }
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setInt32(0, value, true);
    this.#parts.push(bytes);
    return this;
  }

  u64le(value: bigint | number): this {
    const bigint = BigInt(value);
    if (bigint < 0n || bigint > MAX_U64) throw new RangeError(`invalid u64: ${value}`);
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, bigint, true);
    this.#parts.push(bytes);
    return this;
  }

  i64le(value: bigint | number): this {
    const bigint = BigInt(value);
    if (bigint < -0x8000_0000_0000_0000n || bigint > 0x7fff_ffff_ffff_ffffn) {
      throw new RangeError(`invalid i64: ${value}`);
    }
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigInt64(0, bigint, true);
    this.#parts.push(bytes);
    return this;
  }

  bytes(value: Uint8Array): this {
    this.#parts.push(value.slice());
    return this;
  }

  compactSize(value: bigint | number): this {
    const bigint = BigInt(value);
    if (bigint < 0n || bigint > MAX_U64) throw new RangeError(`invalid CompactSize: ${value}`);
    if (bigint < 0xfdn) return this.u8(Number(bigint));
    if (bigint <= 0xffffn) {
      this.u8(0xfd);
      const bytes = new Uint8Array(2);
      new DataView(bytes.buffer).setUint16(0, Number(bigint), true);
      this.#parts.push(bytes);
      return this;
    }
    if (bigint <= 0xffff_ffffn) {
      this.u8(0xfe);
      return this.u32le(Number(bigint));
    }
    this.u8(0xff);
    return this.u64le(bigint);
  }

  varBytes(value: Uint8Array): this {
    return this.compactSize(value.length).bytes(value);
  }

  varString(value: string): this {
    return this.varBytes(utf8ToBytes(value));
  }

  finish(): Uint8Array {
    return concatBytes(...this.#parts);
  }

  #integer(value: number, max: number, name: string): void {
    if (!Number.isInteger(value) || value < 0 || value > max) {
      throw new RangeError(`invalid ${name}: ${value}`);
    }
  }
}
