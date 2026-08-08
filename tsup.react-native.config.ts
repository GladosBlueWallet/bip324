import { readFileSync } from "node:fs";
import { defineConfig } from "tsup";

export default defineConfig({
  entry: { "react-native": "src/react-native.ts" },
  format: ["esm"],
  dts: true,
  sourcemap: true,
  splitting: false,
  platform: "neutral",
  noExternal: [/.*/],
  banner: {
    js: readFileSync(new URL("./src/polyfills/text-encoder.js", import.meta.url), "utf8"),
  },
});
