import { utf8ToBytes as nobleUtf8ToBytes } from "@noble/hashes/utils.js";

export function utf8ToBytes(value: string): Uint8Array {
  return nobleUtf8ToBytes(value);
}

export function bytesToUtf8(bytes: Uint8Array): string {
  const units: number[] = [];
  let output = "";
  const flush = () => {
    if (units.length > 0) {
      output += String.fromCharCode(...units);
      units.length = 0;
    }
  };
  const continuation = (index: number): number => {
    const byte = bytes[index];
    if (byte === undefined || (byte & 0xc0) !== 0x80) throw new Error("invalid UTF-8");
    return byte;
  };

  for (let i = 0; i < bytes.length;) {
    const first = bytes[i++]!;
    let codePoint: number;
    if (first <= 0x7f) {
      codePoint = first;
    } else if (first >= 0xc2 && first <= 0xdf) {
      codePoint = ((first & 0x1f) << 6) | (continuation(i++) & 0x3f);
    } else if (first >= 0xe0 && first <= 0xef) {
      const second = continuation(i++);
      const third = continuation(i++);
      if ((first === 0xe0 && second < 0xa0) || (first === 0xed && second >= 0xa0)) {
        throw new Error("invalid UTF-8");
      }
      codePoint = ((first & 0x0f) << 12) | ((second & 0x3f) << 6) | (third & 0x3f);
    } else if (first >= 0xf0 && first <= 0xf4) {
      const second = continuation(i++);
      const third = continuation(i++);
      const fourth = continuation(i++);
      if ((first === 0xf0 && second < 0x90) || (first === 0xf4 && second >= 0x90)) {
        throw new Error("invalid UTF-8");
      }
      codePoint =
        ((first & 0x07) << 18) |
        ((second & 0x3f) << 12) |
        ((third & 0x3f) << 6) |
        (fourth & 0x3f);
    } else {
      throw new Error("invalid UTF-8");
    }

    if (codePoint <= 0xffff) {
      units.push(codePoint);
    } else {
      const adjusted = codePoint - 0x10000;
      units.push(0xd800 + (adjusted >> 10), 0xdc00 + (adjusted & 0x3ff));
    }
    if (units.length >= 4096) flush();
  }
  flush();
  return output;
}
