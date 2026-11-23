import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, symlinkSync, readFileSync, readdirSync, mkdirSync } from "node:fs";
import { tmpdir, platform, arch } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const here = fileURLToPath(new URL(".", import.meta.url));
const script = join(here, "install-bun-from-pin.sh");
const allow = JSON.parse(readFileSync(join(here, "../config/bun-runtimes.json"), "utf8"));
const linuxX64 = platform() === "linux" && arch() === "x64";

function run(pinText, { asSymlink = false, zip } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "bun-from-pin-"));
  const real = join(dir, "pin.real");
  writeFileSync(real, pinText);
  const pin = asSymlink ? join(dir, "pin") : real;
  if (asSymlink) symlinkSync(real, pin);
  const args = [script, pin, ...(zip ? ["--zip", zip] : [])];
  return spawnSync("bash", args, { encoding: "utf8", env: { PATH: process.env.PATH, RUNNER_TEMP: dir } });
}

test("allowlist: only well-formed hashes, current release 1.4.5 present", () => {
  for (const [version, entry] of Object.entries(allow["linux-x64"])) {
    assert.match(version, /^\d+\.\d+\.\d+$/);
    assert.match(entry.zip_sha256, /^[0-9a-f]{64}$/);
    assert.match(entry.bun_sha256, /^[0-9a-f]{64}$/);
  }
  assert.equal(allow["linux-x64"]["1.4.5"].bun_sha256, "f05d28a3862f4b84395c7fa32480b835dd47482e80b7e7a49a115227f0c06083");
});

test("missing, duplicate, malformed or linked pins fail closed before any download", () => {
  for (const text of ["nothing here\n", 'VERSION = "1.4.5"\nVERSION = "1.4.5"\n', 'VERSION = "1.4"\n', 'VERSION = "1.4.5" # x\n']) {
    const r = run(text);
    assert.notEqual(r.status, 0, text);
  }
  assert.notEqual(run('VERSION = "1.4.5"\n', { asSymlink: true }).status, 0);
});

test("a version outside the allowlist is refused", { skip: !linuxX64 && "nur Linux x64" }, () => {
  const r = run('VERSION = "1.3.14"\n');
  assert.equal(r.status, 66);
  assert.match(r.stderr, /not allowed/);
});

test("an archive with the wrong hash is refused", { skip: !linuxX64 && "nur Linux x64" }, () => {
  const dir = mkdtempSync(join(tmpdir(), "bun-zip-"));
  const zip = join(dir, "bogus.zip");
  writeFileSync(zip, "not a bun archive");
  const r = run('VERSION = "1.4.5"\n', { zip });
  assert.equal(r.status, 67);
  assert.match(r.stderr, /archive hash mismatch/);
});

test("the real 1.4.5 archive installs and reports exactly the pinned version", { skip: !(linuxX64 && process.env.BUN_145_ZIP) && "BUN_145_ZIP (geprüftes Archiv) nur auf Linux x64" }, () => {
  const r = run('# Pin\nVERSION = "1.4.5"\n', { zip: process.env.BUN_145_ZIP });
  assert.equal(r.status, 0, r.stderr);
  const bin = r.stdout.trim();
  assert.equal(spawnSync(join(bin, "bun"), ["--version"], { encoding: "utf8" }).stdout.trim(), "1.4.5");
});

// Verdrahtung: Jobs, die eine private Quelle mit Bun-Pin prüfen, richten Bun ohne fremde Action nach dem Checkout
// aus dem Quell-Pin ein; die Gleichheitsprüfung folgt danach, beides vor jeder Ausführung von Quellcode.
const workflows = readdirSync(new URL("../.github/workflows/", import.meta.url))
  .filter((n) => n.endsWith(".yml"))
  .map((name) => ({ name, text: readFileSync(new URL(`../.github/workflows/${name}`, import.meta.url), "utf8") }));
const jobs = workflows.flatMap(({ name, text }) => text.split(/\n(?=  [a-z0-9_-]+:\n)/).map((job) => ({ name, job })))
  .filter(({ job }) => job.includes("verify-bun-runtime-pin.sh"));

test("all pin-verifying jobs are covered (u1-chat and atlas in their PR checks and the fleet check)", () => {
  assert.equal(jobs.length, 4);
});
for (const { name, job } of jobs) test(`${name}: Bun aus dem Quell-Pin nach dem Checkout, ohne setup-bun`, () => {
  assert.doesNotMatch(job, /setup-bun|bun-version:/);
  const checkout = job.indexOf("checkout-private-source.sh ");
  const install = job.indexOf('gate/scripts/install-bun-from-pin.sh"');
  const verify = job.indexOf('gate/scripts/verify-bun-runtime-pin.sh"');
  assert.ok(checkout > 0 && checkout < install && install < verify, "Reihenfolge Checkout < Einrichten < Prüfen");
  const step = job.slice(job.lastIndexOf("      - name:", install), job.indexOf("      - name:", install));
  assert.match(step, /run: bash "\$GITHUB_WORKSPACE\/gate\/scripts\/run-confidential\.sh" [a-z0-9-]+-bun-install bash/);
  assert.doesNotMatch(step, /(?:continue-on-error|if):/);
  const pinArg = step.match(/install-bun-from-pin\.sh" (\S+)/)[1];
  const verifyStep = job.slice(job.lastIndexOf("      - name:", verify), job.indexOf("      - name:", verify));
  assert.ok(verifyStep.includes(`verify-bun-runtime-pin.sh" ${pinArg}`), "beide Schritte lesen denselben Pin");
  const firstUse = Math.min(...["npm ci", "bun install", "bun test", "bun run"].map((s) => job.indexOf(s, checkout)).filter((i) => i > 0));
  assert.ok(verify < firstUse, "Prüfung vor erster Ausführung von Quellcode");
});
