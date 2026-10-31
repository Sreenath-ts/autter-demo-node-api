import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

function readJson(relativePath: string) {
  return JSON.parse(readFileSync(new URL(relativePath, import.meta.url), "utf8"));
}

const manifest = readJson("../package.json");
const lock = readJson("../package-lock.json");

describe("CVE dependency bumps", () => {
  test("vite is bumped to the fixed version 8.3.3 (GHSA-587h-7wmj-h5pm)", () => {
    expect(lock.packages["node_modules/vite"].version).toBe("8.3.3");
  });

  test("zod is bumped to the fixed version 4.6.6 (GHSA-mrhx-c7xc-m3w5)", () => {
    expect(manifest.dependencies.zod).toBe("^4.6.6");
    expect(lock.packages[""].dependencies.zod).toBe("^4.6.6");
    expect(lock.packages["node_modules/zod"].version).toBe("4.6.6");
  });
});
