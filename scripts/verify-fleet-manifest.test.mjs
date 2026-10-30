import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve, dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { validateManifest } from "./verify-fleet-manifest.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const fixture = JSON.parse(readFileSync(join(ROOT, "fleet/manifests/scai-candidate-2026-08-24.1.json"), "utf8"));
const clone = () => structuredClone(fixture);

test("superseded historical candidate remains structurally valid", () => {
  assert.deepEqual(validateManifest(clone()), []);
});

test("superseded status requires a complete, different source binding", () => {
  const missing = clone();
  delete missing.supersession;
  assert.match(validateManifest(missing).join("\n"), /root fields must match schema exactly/);

  const sameSource = clone();
  sameSource.supersession.superseded_by_source_sha = sameSource.pins.scai_source.sha;
  assert.match(validateManifest(sameSource).join("\n"), /supersession must point to a different SCAI source SHA/);
});

test("an active candidate cannot retain historical supersession metadata", () => {
  const manifest = clone();
  manifest.status = "candidate";
  assert.match(validateManifest(manifest).join("\n"), /root fields must match schema exactly/);

  delete manifest.supersession;
  assert.deepEqual(validateManifest(manifest), []);
});

test("short component SHAs are rejected", () => {
  const manifest = clone();
  manifest.pins.atlas.sha = "dd60d554";
  assert.match(validateManifest(manifest).join("\n"), /atlas\.sha must be a full 40-character Git SHA/);
});

test("all A-gates must refer to the exact same release pin", () => {
  const manifest = clone();
  manifest.gates.A4.release_pin = "another-release";
  assert.match(validateManifest(manifest).join("\n"), /A4\.release_pin must equal release_id/);
});

test("unknown fields are rejected instead of silently ignored", () => {
  const manifest = clone();
  manifest.pins.atlas.unverified_note = "looks fine";
  assert.match(validateManifest(manifest).join("\n"), /atlas fields must match schema exactly/);
});

test("aggregate artifact PASS cannot hide an open platform", () => {
  const manifest = clone();
  manifest.artifacts.status = "pass";
  assert.match(validateManifest(manifest).join("\n"), /artifacts PASS requires every platform to PASS/);
});

test("platform PASS cannot conflate updater and native code signatures", () => {
  const manifest = clone();
  const artifact = manifest.artifacts.platforms.windows_x64;
  Object.assign(artifact, {
    status: "pass",
    artifact_url: "https://example.invalid/scai.exe",
    sha256: "a".repeat(64),
    updater_signature_url: "https://example.invalid/scai.exe.sig",
    updater_signature_verified: true,
    sbom_url: "https://example.invalid/scai.cdx.json",
    sbom_sha256: "b".repeat(64),
    provenance_url: "https://example.invalid/attestation/1",
    provenance_verified: true,
  });
  const errors = validateManifest(manifest).join("\n");
  assert.match(errors, /windows_x64 PASS requires native code-signature PASS/);
  assert.match(errors, /windows_x64 PASS requires a named code signer/);
  assert.match(errors, /windows_x64 PASS requires code-signature evidence/);
});

test("operations PASS must be pinned, timed, operated and independently judged", () => {
  const manifest = clone();
  Object.assign(manifest.operations, {
    status: "pass",
    deployed: true,
    health_verified: true,
    recovery_verified: true,
    rollback_verified: true,
    evidence_url: "https://example.invalid/ops.json",
    evidence_sha256: "c".repeat(64),
  });
  const errors = validateManifest(manifest).join("\n");
  assert.match(errors, /operations PASS requires environment/);
  assert.match(errors, /operations PASS requires a named operator/);
  assert.match(errors, /operations PASS requires an independent judge/);
  assert.match(errors, /operations PASS requires started_at/);
  assert.match(errors, /operations PASS requires completed_at/);
});

test("market PASS cannot replace three primary customer proofs with one URL", () => {
  const manifest = clone();
  manifest.market_gates.R3.status = "pass";
  manifest.market_gates.R3.evidence = ["https://example.invalid/customer-proof"];
  const errors = validateManifest(manifest).join("\n");
  assert.match(errors, /R3 PASS requires at least 3 distinct primary evidence URLs/);
});

test("market evidence needs a pinned report, separate attestation and three paying customers", () => {
  const manifest = clone();
  for (const id of ["R0", "R1", "R2", "R3"]) {
    manifest.market_gates[id].status = "pass";
    manifest.market_gates[id].evidence = id === "R3"
      ? ["https://example.invalid/c1", "https://example.invalid/c2", "https://example.invalid/c3"]
      : [`https://example.invalid/${id}`];
  }
  Object.assign(manifest.market_evidence, {
    status: "pass",
    report_url: "https://example.invalid/market-report",
    report_sha256: "d".repeat(64),
    validator_name: "Independent Market Judge",
    validator_role: "external review",
    validated_at: "2026-08-25T12:00:00Z",
    attestation_url: "https://example.invalid/market-report",
    attestation_sha256: "e".repeat(64),
    repeatable_paying_customers: 2,
  });
  const errors = validateManifest(manifest).join("\n");
  assert.match(errors, /report and independent attestation must be distinct/);
  assert.match(errors, /at least three repeatable paying customers/);

  manifest.market_gates.R3.owner = "Independent Market Judge";
  assert.match(validateManifest(manifest).join("\n"), /validator must be independent of the market gate owners/);
});

test("a cosmetic top-level PASS fails closed while evidence remains open", () => {
  const manifest = clone();
  manifest.status = "pass";
  delete manifest.supersession;
  manifest.pins.u1_chat.merge_status = "open";
  const errors = validateManifest(manifest).join("\n");
  assert.match(errors, /PASS requires an empty blocker list/);
  assert.match(errors, /PASS requires every pin to be merged/);
  assert.match(errors, /PASS requires A1-A8 to PASS/);
  assert.match(errors, /PASS requires market gates R0-R3 to PASS/);
  assert.match(errors, /PASS requires independently attested market evidence/);
  assert.match(errors, /PASS requires governance status PASS/);
  assert.match(errors, /PASS requires operations status PASS/);
});

// Org-Umzug (TJ 2026-10-30): Pins dürfen genau auf subunit-ai/<repo> (historisch) oder
// Subunit-UG/<repo> zeigen, Groß-/Kleinschreibung des Owners egal. Alles andere bleibt zu.
for (const repository of [
  "https://github.com/subunit-ai/subunit-scai",
  "https://github.com/Subunit-UG/scai-app",
  "https://github.com/subunit-ug/infra-atlas",
  "https://github.com/SUBUNIT-AI/echo",
]) test(`Pin-Owner nach Org-Umzug zugelassen: ${repository}`, () => {
  const manifest = clone();
  manifest.pins.scai_source.repository = repository;
  manifest.pins.atlas.repository = repository;
  assert.deepEqual(validateManifest(manifest), []);
});

for (const repository of [
  "https://github.com/attacker/scai-app",
  "https://github.com/Subunit-UG-evil/scai-app",
  "https://github.com/evil-subunit-ai/scai-app",
  "https://github.com/subunit/scai-app",
  "https://github.com/Subunit-UG/scai-app/",
  "https://github.com/Subunit-UG/scai-app/pull/1",
  "https://github.com/Subunit-UG",
  "https://github.com.attacker.invalid/Subunit-UG/scai-app",
  "http://github.com/Subunit-UG/scai-app",
  "https://github.com/subunit-a\u0131/scai-app",
  "https://github.com/subunit-a\u0130/scai-app",
  "https://github.com/subunit-ai/scai-app\n",
  "",
]) test(`fremder oder unscharfer Pin-Owner abgewiesen: ${JSON.stringify(repository)}`, () => {
  const manifest = clone();
  manifest.pins.scai_source.repository = repository;
  assert.match(validateManifest(manifest).join("\n"), /scai_source\.repository must be an approved GitHub repository/);
});
