import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
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

test("Atlas checks its API/worker pin confidentially after checkout and before source execution", () => {
  const workflow = readFileSync(new URL("../.github/workflows/atlas-pr-check.yml", import.meta.url), "utf8");
  const setup = workflow.indexOf("bun-version: 1.4.4");
  const checkout = workflow.indexOf('run: bash gate/scripts/checkout-private-source.sh atlas');
  const pin = workflow.indexOf('atlas-bun-pin bash "$GITHUB_WORKSPACE/gate/scripts/verify-bun-runtime-pin.sh" bun-runtime.pin');
  const install = workflow.indexOf("atlas-web-install npm ci");
  assert.ok(setup > 0 && setup < checkout && checkout < pin && pin < install);
  const step = workflow.slice(workflow.lastIndexOf("      - name:", pin), workflow.indexOf("      - name:", pin));
  assert.match(step, /working-directory: private\/atlas\/atlas-api/);
  assert.match(step, /run: bash "\$GITHUB_WORKSPACE\/gate\/scripts\/run-confidential\.sh" atlas-bun-pin/);
  assert.doesNotMatch(step, /(?:continue-on-error|if):/);
  assert.equal(run('# API and worker runtime\nVERSION = "1.4.4"\n', "1.4.4").status, 0);
});
