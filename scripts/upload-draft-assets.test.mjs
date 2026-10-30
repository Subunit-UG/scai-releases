import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join, resolve, dirname } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const script = join(ROOT, "scripts/upload-draft-assets.sh");
const sourceSha = "a".repeat(40);
const releaseId = "scai-candidate-2026-09-09.9";

function runGuard({ isDraft = true, tagName = "v1.2.3", body, asset = true } = {}) {
  const fixture = mkdtempSync(join(tmpdir(), "scai-draft-upload-"));
  const bin = join(fixture, "bin");
  const gh = join(bin, "gh");
  const log = join(fixture, "gh.log");
  const assetPath = join(fixture, "artifact.bin");
  spawnSync("mkdir", ["-p", bin], { encoding: "utf8" });
  writeFileSync(gh, `#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$FAKE_GH_LOG"
if [ "$1 $2" = "release view" ]; then
  printf '%s\\n' "$FAKE_RELEASE_JSON"
  exit 0
fi
if [ "$1 $2" = "release upload" ]; then exit 0; fi
exit 2
`);
  chmodSync(gh, 0o755);
  if (asset) writeFileSync(assetPath, "artifact");
  const boundBody = body ?? [
    `Source-SHA: ${sourceSha}`,
    `Fleet-Release-ID: ${releaseId}`,
    "Distribution-Policy: market-ready",
  ].join("\n");
  const result = spawnSync("bash", [script, assetPath], {
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${bin}${delimiter}${process.env.PATH}`,
      FAKE_GH_LOG: log,
      FAKE_RELEASE_JSON: JSON.stringify({ isDraft, tagName, body: boundBody }),
      REPO: "Subunit-UG/scai-releases",
      TAG: "v1.2.3",
      SOURCE_SHA: sourceSha,
      RELEASE_ID: releaseId,
      DISTRIBUTION_POLICY: "market-ready",
    },
  });
  return { ...result, calls: readFileSync(log, "utf8") };
}

test("matching bound draft permits the intentional retry upload", () => {
  const result = runGuard();
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.calls, /release upload v1\.2\.3 .*artifact\.bin -R Subunit-UG\/scai-releases --clobber/);
});

test("published release is immutable", () => {
  const result = runGuard({ isDraft: false });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr + result.stdout, /bereits veröffentlicht/);
  assert.doesNotMatch(result.calls, /release upload/);
});

test("release lookup must return the exact requested tag", () => {
  const result = runGuard({ tagName: "v1.2.4" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr + result.stdout, /Release-Tag stimmt nicht/);
  assert.doesNotMatch(result.calls, /release upload/);
});

for (const [name, replacement] of [
  ["source", `Source-SHA: ${"b".repeat(40)}`],
  ["release id", "Fleet-Release-ID: scai-candidate-2026-09-09.10"],
  ["policy", "Distribution-Policy: legacy-v0.125"],
]) {
  test(`draft with mismatched ${name} cannot be clobbered`, () => {
    const body = [
      replacement,
      ...(name === "source" ? [] : [`Source-SHA: ${sourceSha}`]),
      ...(name === "release id" ? [] : [`Fleet-Release-ID: ${releaseId}`]),
      ...(name === "policy" ? [] : ["Distribution-Policy: market-ready"]),
    ].join("\n");
    const result = runGuard({ body });
    assert.notEqual(result.status, 0);
    assert.doesNotMatch(result.calls, /release upload/);
  });
}

test("missing asset cannot reach gh upload", () => {
  const result = runGuard({ asset: false });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr + result.stdout, /Ungültiger Draft-Asset-Pfad/);
  assert.doesNotMatch(result.calls, /release upload/);
});

for (const [field, suffix] of [
  ["Source-SHA", "a"],
  ["Fleet-Release-ID", "0"],
  ["Distribution-Policy", "-other"],
]) {
  test(`draft ${field} must match the complete value, not a prefix`, () => {
    const body = [
      `Source-SHA: ${sourceSha}`,
      `Fleet-Release-ID: ${releaseId}`,
      "Distribution-Policy: market-ready",
    ].map((line) => line.startsWith(`${field}:`) ? `${line}${suffix}` : line).join("\n");
    const result = runGuard({ body });
    assert.notEqual(result.status, 0);
    assert.doesNotMatch(result.calls, /release upload/);
  });
}
