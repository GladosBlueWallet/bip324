export type ByteReader = {
  /** Return 0 at EOF, or between 1 and n bytes. */
  read(n: number): Promise<Uint8Array>;
};

/** Read exactly n bytes, accepting arbitrary stream fragmentation. */
export async function readExactly(reader: ByteReader, n: number): Promise<Uint8Array> {
  if (!Number.isSafeInteger(n) || n < 0) throw new RangeError(`invalid read length: ${n}`);
  const out = new Uint8Array(n);
  let offset = 0;
  while (offset < n) {
    const chunk = await reader.read(n - offset);
    if (chunk.length === 0) {
      throw new Error(`unexpected EOF: wanted ${n} bytes, got ${offset}`);
    }
    if (chunk.length > n - offset) {
      throw new Error(`reader returned ${chunk.length} bytes when at most ${n - offset} were requested`);
    }
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}
