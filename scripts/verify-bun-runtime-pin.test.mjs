import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const script = join(fileURLToPath(new URL(".", import.meta.url)), "verify-bun-runtime-pin.sh");

function run(pinText, bunVersion, { asSymlink = false } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "bun-pin-"));
  try {
    const bin = join(dir, "bin");
    spawnSync("mkdir", [bin]);
    writeFileSync(join(bin, "bun"), `#!/bin/sh\nprintf '%s\\n' '${bunVersion}'\n`);
    chmodSync(join(bin, "bun"), 0o755);
    const real = join(dir, "install-bun-runtime.py");
    writeFileSync(real, pinText);
    let pin = real;
    if (asSymlink) {
      pin = join(dir, "pin-link.py");
      symlinkSync(real, pin);
    }
    return spawnSync("bash", [script, pin], { env: { PATH: `${bin}:/usr/bin:/bin` }, encoding: "utf8" });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("passes only when CI runtime equals the source pin", () => {
  const ok = run('X = 1\nVERSION = "1.4.4"\n', "1.4.4");
  assert.equal(ok.status, 0, ok.stderr);
  assert.match(ok.stdout, /PASS bun runtime pin \(bun=1\.4\.4\)/);
});

test("drift between CI runtime and source pin fails closed", () => {
  const drift = run('VERSION = "1.4.4"\n', "1.3.14");
  assert.equal(drift.status, 1);
  assert.match(drift.stderr, /bun runtime drift: CI 1\.3\.14, source pin 1\.4\.4/);
});

test("missing, duplicate, malformed or linked pins fail closed", () => {
  assert.notEqual(run("nothing here\n", "1.4.4").status, 0);
  assert.notEqual(run('VERSION = "1.4.4"\nVERSION = "1.4.4"\n', "1.4.4").status, 0);
  assert.notEqual(run('VERSION = "1.4"\n', "1.4").status, 0);
  assert.notEqual(run('VERSION = "1.4.4"\n', "garbage").status, 0);
  assert.notEqual(run('VERSION = "1.4.4"\n', "1.4.4", { asSymlink: true }).status, 0);
});
