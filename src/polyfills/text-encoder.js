if (typeof globalThis.TextEncoder !== "function") {
  class TextEncoderPolyfill {
    encoding = "utf-8";

    encode(input = "") {
      const bytes = [];
      for (const symbol of input) {
        let codePoint = symbol.codePointAt(0);
        if (codePoint >= 0xd800 && codePoint <= 0xdfff) codePoint = 0xfffd;
        if (codePoint <= 0x7f) {
          bytes.push(codePoint);
        } else if (codePoint <= 0x7ff) {
          bytes.push(0xc0 | (codePoint >> 6), 0x80 | (codePoint & 0x3f));
        } else if (codePoint <= 0xffff) {
          bytes.push(
            0xe0 | (codePoint >> 12),
            0x80 | ((codePoint >> 6) & 0x3f),
            0x80 | (codePoint & 0x3f),
          );
        } else {
          bytes.push(
            0xf0 | (codePoint >> 18),
            0x80 | ((codePoint >> 12) & 0x3f),
            0x80 | ((codePoint >> 6) & 0x3f),
            0x80 | (codePoint & 0x3f),
          );
        }
      }
      return new Uint8Array(bytes);
    }
  }

  Object.defineProperty(globalThis, "TextEncoder", {
    configurable: true,
    writable: true,
    value: TextEncoderPolyfill,
  });
}
