import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const dir = path.dirname(fileURLToPath(import.meta.url));
const script = path.join(dir, "apt-bundle.sh");
const run = (...args) => spawnSync("bash", [script, ...args], { encoding: "utf8" });

test("rejects unsafe bundle names before doing anything", () => {
  for (const name of ["", "../x", "a b", "A", "-x", "x".repeat(65)]) {
    const r = run("install", name, "0".repeat(64), "ffmpeg");
    assert.equal(r.status, 2, name);
    assert.match(r.stderr, /invalid bundle name/);
  }
});

test("install requires a pinned sha256 and at least one package", () => {
  assert.equal(run("install", "ffmpeg-ubuntu-24.04", "abc", "ffmpeg").status, 2);
  assert.match(run("install", "ffmpeg-ubuntu-24.04", "abc", "ffmpeg").stderr, /pinned sha256 required/);
  assert.match(run("install", "ffmpeg-ubuntu-24.04", "0".repeat(64)).stderr, /no packages/);
});

test("unknown mode prints usage", () => {
  const r = run("frob", "ffmpeg-ubuntu-24.04");
  assert.equal(r.status, 2);
  assert.match(r.stderr, /usage/);
});

test("the bundle is only ever installed after its sha256 matched the pin", () => {
  const src = readFileSync(script, "utf8");
  const check = src.indexOf('[[ "$got" == "$want" ]]');
  const dpkg = src.indexOf("sudo dpkg -i");
  assert.ok(check > 0 && dpkg > check, "dpkg runs only inside the matched-sha branch");
  assert.ok(src.includes('sha256sum -c --quiet SHA256SUMS) && { ((${#new[@]} == 0)) || sudo dpkg -i "${new[@]}"'));
  assert.ok(src.includes('installed "$pkg" || new+=("$deb")'), "already installed packages are never replaced");
});

test("refresh workflow is manual, passes inputs via env and pins its actions", () => {
  const wf = readFileSync(path.join(dir, "..", ".github", "workflows", "apt-bundles.yml"), "utf8");
  assert.match(wf, /workflow_dispatch:/);
  assert.doesNotMatch(wf, /run: \|[\s\S]*\$\{\{ inputs\.bundle \}\}[\s\S]*?\n\s+- /, "inputs only via env");
  for (const uses of wf.match(/uses: \S+/g) ?? []) assert.match(uses, /@[0-9a-f]{40}$/, uses);
});

test("recommends follow the caller: off by default, on with APT_BUNDLE_RECOMMENDS=1", () => {
  const src = readFileSync(script, "utf8");
  assert.match(src, /REC=\(--no-install-recommends\)/);
  assert.match(src, /\[\[ "\$\{APT_BUNDLE_RECOMMENDS:-0\}" == 1 \]\] && REC=\(\)/);
  assert.equal((src.match(/install -y "\$\{REC\[@\]\}"/g) ?? []).length, 2, "bundle build and apt fallback use the same set");
});
