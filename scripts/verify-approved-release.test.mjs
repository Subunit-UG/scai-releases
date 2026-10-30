import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { verifyApprovedRelease } from "./verify-approved-release.mjs";
import { validateManifest } from "./verify-fleet-manifest.mjs";
import { releaseAssetNames, validateReleaseAuthorization } from "./release-authorization.mjs";

// Kanonisch seit dem Org-Umzug (TJ 2026-10-30); LEGACY ist die weitergeleitete alte Adresse.
const repository = "Subunit-UG/scai-releases";
const LEGACY = "subunit-ai/scai-releases";
const tag = "v1.2.3";
const source = "a".repeat(40);
const releaseId = "scai-candidate-2026-09-15.1";
const hash = bytes => createHash("sha256").update(bytes).digest("hex");
const url = name => `https://github.com/${repository}/releases/download/${tag}/${name}`;
const targets = ["aarch64-apple-darwin", "x86_64-apple-darwin", "aarch64-pc-windows-msvc", "x86_64-pc-windows-msvc", "x86_64-unknown-linux-gnu"];
const platformFiles = {
  macos_arm64: ["SCAI_1.2.3_aarch64.dmg", "SCAI_aarch64.app.tar.gz.sig", targets[0]],
  macos_x64: ["SCAI_1.2.3_x64.dmg", "SCAI_x64.app.tar.gz.sig", targets[1]],
  windows_arm64: ["SCAI_1.2.3_arm64-setup.exe", "SCAI_1.2.3_arm64-setup.exe.sig", targets[2]],
  windows_x64: ["SCAI_1.2.3_x64-setup.exe", "SCAI_1.2.3_x64-setup.exe.sig", targets[3]],
  linux_x64: ["SCAI_1.2.3_amd64.AppImage", "SCAI_1.2.3_amd64.AppImage.sig", targets[4]],
};
const updaterFiles = {
  "darwin-aarch64": "SCAI_aarch64.app.tar.gz", "darwin-aarch64-app": "SCAI_aarch64.app.tar.gz",
  "darwin-x86_64": "SCAI_x64.app.tar.gz", "darwin-x86_64-app": "SCAI_x64.app.tar.gz",
  "windows-aarch64": "SCAI_1.2.3_arm64-setup.exe", "windows-aarch64-nsis": "SCAI_1.2.3_arm64-setup.exe",
  "windows-x86_64": "SCAI_1.2.3_x64-setup.exe", "windows-x86_64-nsis": "SCAI_1.2.3_x64-setup.exe",
  "linux-x86_64": "SCAI_1.2.3_amd64.AppImage", "linux-x86_64-appimage": "SCAI_1.2.3_amd64.AppImage", "linux-x86_64-deb": "SCAI_1.2.3_amd64.deb",
};

function fixture(t, policy = "market-ready", repos = {}) {
  // Schreibweise je Quelle: Freigabe, Draft-API, latest.json und Manifest-Artefakte.
  const spell = { approval: repository, remote: repository, updater: repository, artifacts: repository, ...repos };
  const at = (repo, name) => `https://github.com/${repo}/releases/download/${tag}/${name}`;
  const root = mkdtempSync(join(tmpdir(), "scai-approved-release-test-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const dir = join(root, "assets");
  mkdirSync(dir);
  const manifest = JSON.parse(readFileSync(new URL("../fleet/manifests/scai-candidate-2026-08-24.1.json", import.meta.url)));
  delete manifest.supersession;
  Object.assign(manifest, { status: "pass", release_id: releaseId, blockers: [] });
  for (const pin of Object.values(manifest.pins)) Object.assign(pin, { merge_status: "merged", pr_url: `${pin.repository}/pull/1` });
  manifest.pins.scai_source.sha = source;
  for (const [id, gate] of Object.entries(manifest.gates)) Object.assign(gate, { release_pin: releaseId, status: "pass", owner: `owner-${id}`, judge: `judge-${id}`, evidence: [`https://evidence.invalid/${id}`] });
  for (const [id, gate] of Object.entries(manifest.market_gates)) Object.assign(gate, { status: "pass", owner: `owner-${id}`, evidence: [1, 2, 3].map(n => `https://evidence.invalid/${id}/${n}`) });
  Object.assign(manifest.market_evidence, { status: "pass", release_pin: releaseId, source_sha: source, report_url: "https://evidence.invalid/market", report_sha256: hash("market"), validator_name: "independent", validator_role: "judge", validated_at: "2026-09-15T00:00:00Z", attestation_url: "https://evidence.invalid/attestation", attestation_sha256: hash("attestation"), repeatable_paying_customers: 3 });
  Object.assign(manifest.source_ci, { status: "pass", sha: source, run_url: "https://evidence.invalid/ci" });
  Object.assign(manifest.governance, { status: "pass", release_pin: releaseId, legal_owner: "legal", dpo_owner: "dpo", independent_judge: "judge", decision: "approved", evidence_url: "https://evidence.invalid/governance", evidence_sha256: hash("governance") });
  Object.assign(manifest.operations, { status: "pass", release_pin: releaseId, environment: "fixture", operator: "operator", independent_judge: "judge", started_at: "2026-09-15T00:00:00Z", completed_at: "2026-09-15T00:01:00Z", deployed: true, health_verified: true, recovery_verified: true, rollback_verified: true, evidence_url: "https://evidence.invalid/operations", evidence_sha256: hash("operations") });
  for (const [role, approval] of Object.entries(manifest.approvals)) Object.assign(approval, { name: role, evidence_url: `https://evidence.invalid/${role}`, evidence_sha256: hash(role) });
  const contents = new Map();
  for (const name of new Set([...Object.values(updaterFiles), ...Object.values(platformFiles).map(record => record[0])])) contents.set(name, Buffer.from([0, 255, 128, 10]));
  for (const name of new Set(Object.values(updaterFiles))) contents.set(`${name}.sig`, Buffer.from(`synthetic-signature-for-${name}\n`));
  contents.set("scai.cdx.json", Buffer.from('{"bomFormat":"CycloneDX"}\n'));
  for (const target of targets) contents.set(`runtime-evidence-${target}.json`, Buffer.from('{"fixture":true}\n'));
  for (const target of targets.slice(0, 4)) contents.set(`signing-evidence-${target}.json`, Buffer.from(JSON.stringify({ status: "pass", platform: target, distribution_policy: policy })));
  const latest = { version: "1.2.3", source_sha: source, platforms: Object.fromEntries(Object.entries(updaterFiles).map(([key, name]) => [key, { url: at(spell.updater, name), signature: contents.get(`${name}.sig`).toString().trim() }])) };
  contents.set("latest.json", Buffer.from(JSON.stringify(latest)));
  manifest.authorized_release = { repository: spell.approval, tag, distribution_policy: policy, assets: [] };
  const release = { tag_name: tag, draft: true, prerelease: false, body: `Source-SHA: ${source}\nFleet-Release-ID: ${releaseId}\nDistribution-Policy: ${policy}`, assets: [] };
  const sums = () => [...contents].filter(([name]) => name !== "SHA256SUMS").sort(([a], [b]) => a.localeCompare(b)).map(([name, bytes]) => `${hash(bytes)}  ${name}\n`).join("");
  function approve({ replaceSums = true } = {}) {
    if (replaceSums) contents.set("SHA256SUMS", Buffer.from(sums()));
    manifest.authorized_release.assets = [...contents].map(([name, bytes]) => ({ name, url: at(spell.approval, name), sha256: hash(bytes) }));
    release.assets = [...contents].map(([name, bytes]) => ({ name, browser_download_url: at(spell.remote, name), digest: `sha256:${hash(bytes)}`, state: "uploaded", size: bytes.length }));
    for (const [name, bytes] of contents) writeFileSync(join(dir, name), bytes);
  }
  approve();
  manifest.artifacts.status = "pass";
  for (const [platform, [installer, signature, target]] of Object.entries(platformFiles)) Object.assign(manifest.artifacts.platforms[platform], {
    status: "pass", artifact_url: at(spell.artifacts, installer), sha256: hash(contents.get(installer)), updater_signature_url: at(spell.artifacts, signature), updater_signature_verified: true,
    code_signature_status: platform === "linux_x64" ? "not_applicable" : "pass", code_signer: platform === "linux_x64" ? "" : "fixture signer",
    code_signature_evidence_url: platform === "linux_x64" ? "" : at(spell.artifacts, `signing-evidence-${target}.json`),
    sbom_url: at(spell.artifacts, "scai.cdx.json"), sbom_sha256: hash(contents.get("scai.cdx.json")), provenance_url: "https://evidence.invalid/provenance", provenance_verified: true,
  });
  assert.deepEqual(validateManifest(manifest), [], "synthetic PASS fixture must meet every existing Fleet gate");
  assert.deepEqual(releaseAssetNames(tag), [...contents.keys()].sort());
  function options(extra = {}) {
    const manifestBytes = Buffer.from(JSON.stringify(manifest));
    return { manifestBytes, manifestSha256: hash(manifestBytes), repository, tag, releaseId, release, assetDir: dir, ...extra };
  }
  return { root, dir, contents, manifest, latest, release, approve, sums, options, verify: extra => verifyApprovedRelease(options(extra)) };
}

for (const policy of ["market-ready", "legacy-v0.125"]) test(`${policy}: exact authorized bytes, evidence and eleven updater targets pass`, async t => {
  const f = fixture(t, policy);
  assert.deepEqual(await f.verify(), { scope: "approved-release-bytes", assets: 26, updaterTargets: 11, policy });
  assert.deepEqual(await f.verify({ assetDir: undefined }), { scope: "remote-metadata-only", assets: 26, policy });
});

for (const [name, mutate] of [
  ["missing policy", f => { f.release.body = f.release.body.replace(/\nDistribution-Policy:.*/, ""); }],
  ["wrong policy", f => { f.release.body = f.release.body.replace("market-ready", "legacy-v0.125"); }],
  ["policy prefix", f => { f.release.body += "-other"; }],
  ["duplicate policy", f => { f.release.body += "\nDistribution-Policy: market-ready"; }],
  ["hidden duplicate policy", f => { f.release.body += "\n Distribution-Policy: legacy-v0.125"; }],
  ["source prefix", f => { f.release.body = f.release.body.replace(source, `${source}b`); }],
  ["release ID prefix", f => { f.release.body = f.release.body.replace(releaseId, `${releaseId}0`); }],
  ["another draft tag", f => { f.release.tag_name = "v1.2.4"; }],
  ["published release", f => { f.release.draft = false; }],
  ["prerelease flag mismatch", f => { f.release.prerelease = true; }],
  ["missing authorization", f => { delete f.manifest.authorized_release; }],
  ["unsupported policy", f => { f.manifest.authorized_release.distribution_policy = "market-ready-v1"; }],
  ["unapproved repository", f => { f.manifest.authorized_release.repository = "attacker/scai-releases"; }],
  ["missing approved file", f => { f.manifest.authorized_release.assets.pop(); }],
  ["duplicate approved file", f => { f.manifest.authorized_release.assets[0] = f.manifest.authorized_release.assets[1]; }],
  ["additional approved file", f => { f.manifest.authorized_release.assets.push({ name: "extra.json", url: url("extra.json"), sha256: hash("extra") }); }],
  ["asset path traversal", f => { f.manifest.authorized_release.assets[0].name = "../outside"; }],
  ["asset URL wrong host", f => { f.manifest.authorized_release.assets[0].url = f.manifest.authorized_release.assets[0].url.replace("github.com", "attacker.invalid"); }],
  ["asset URL wrong repository", f => { f.manifest.authorized_release.assets[0].url = f.manifest.authorized_release.assets[0].url.replace(repository, "attacker/scai-releases"); }],
  ["asset URL wrong tag", f => { f.manifest.authorized_release.assets[0].url = f.manifest.authorized_release.assets[0].url.replace(tag, "v1.2.4"); }],
  ["asset URL wrong filename", f => { f.manifest.authorized_release.assets[0].url += ".other"; }],
  ["asset URL query", f => { f.manifest.authorized_release.assets[0].url += "?download=1"; }],
  ["asset URL encoded traversal", f => { f.manifest.authorized_release.assets[0].url = url("%2e%2e/other"); }],
  ["missing remote file", f => { f.release.assets.pop(); }],
  ["duplicate remote file", f => { f.release.assets[0] = f.release.assets[1]; }],
  ["additional remote file", f => { f.release.assets.push({ ...f.release.assets[0], name: "extra.json" }); }],
  ["remote URL mismatch", f => { f.release.assets[0].browser_download_url = url("other.json"); }],
  ["remote digest missing", f => { delete f.release.assets[0].digest; }],
  ["remote digest mismatch", f => { f.release.assets[0].digest = `sha256:${hash("changed")}`; }],
  ["remote upload incomplete", f => { f.release.assets[0].state = "starter"; }],
  ["remote size mismatch", f => { f.release.assets[0].size += 1; }],
  ["Fleet evidence open", f => { f.manifest.gates.A1.status = "open"; }],
  ["non-PASS manifest", f => { f.manifest.status = "rejected"; }],
]) test(`${name}: reject publication`, async t => {
  const f = fixture(t); mutate(f);
  await assert.rejects(f.verify());
});

// Org-Umzug (TJ 2026-10-30): github.repository und browser_download_url liefern nach dem
// Umzug Subunit-UG, Freigaben/Drafts/latest.json von vorher tragen subunit-ai. Beide
// Schreibweisen desselben Repos müssen bestehen, jeder andere Owner bleibt zu.
for (const [label, repos, workflowRepository] of [
  ["Freigabe vor dem Umzug, Veröffentlichung danach", { approval: LEGACY, updater: LEGACY, artifacts: LEGACY }, repository],
  ["Freigabe nach dem Umzug, Draft noch mit alter Adresse", { remote: LEGACY, updater: LEGACY }, repository],
  ["Workflow liefert noch den alten Namen", {}, LEGACY],
  ["Groß-/Kleinschreibung des Owners egal", { approval: "SUBUNIT-AI/scai-releases", remote: "subunit-ug/scai-releases", updater: "Subunit-ug/scai-releases", artifacts: "subunit-AI/scai-releases" }, "SUBUNIT-UG/scai-releases"],
]) test(`Org-Umzug: ${label} besteht`, async t => {
  const f = fixture(t, "market-ready", repos);
  assert.deepEqual(await f.verify({ repository: workflowRepository }), { scope: "approved-release-bytes", assets: 26, updaterTargets: 11, policy: "market-ready" });
  assert.deepEqual(await f.verify({ repository: workflowRepository, assetDir: undefined }), { scope: "remote-metadata-only", assets: 26, policy: "market-ready" });
});

const foreignOwner = (value, owner = "attacker") => value.replace(`https://github.com/${repository}/`, `https://github.com/${owner}/scai-releases/`);
for (const [label, mutate, extra, reason] of [
  ["Workflow-Repo mit fremdem Owner", () => {}, { repository: "attacker/scai-releases" }, /repository differs from approval/],
  ["Workflow-Repo mit Doppelgänger-Owner", () => {}, { repository: "Subunit-UG-evil/scai-releases" }, /repository differs from approval/],
  ["Workflow-Repo mit anderem Namen", () => {}, { repository: "Subunit-UG/scai-releases-fork" }, /repository differs from approval/],
  ["Draft-URL mit fremdem Owner", f => { f.release.assets[0].browser_download_url = foreignOwner(f.release.assets[0].browser_download_url); }, {}, /remote URL differs/],
  ["Draft-URL mit Doppelgänger-Owner", f => { f.release.assets[0].browser_download_url = foreignOwner(f.release.assets[0].browser_download_url, "evil-subunit-ai"); }, {}, /remote URL differs/],
  ["Installer-URL im Manifest mit fremdem Owner", f => { const p = f.manifest.artifacts.platforms.macos_arm64; p.artifact_url = foreignOwner(p.artifact_url); }, {}, /installer URL differs from approval/],
  ["Updater-URL mit fremdem Owner", f => {
    f.latest.platforms["darwin-aarch64"].url = foreignOwner(f.latest.platforms["darwin-aarch64"].url);
    f.contents.set("latest.json", Buffer.from(JSON.stringify(f.latest))); f.approve();
  }, {}, /wrong updater asset URL/],
  ["in sich konsistente Freigabe für fremden Owner", f => {
    const approval = f.manifest.authorized_release; approval.repository = "attacker/scai-releases";
    for (const asset of approval.assets) asset.url = foreignOwner(asset.url);
  }, {}, /Fleet manifest must satisfy all existing gates/],
]) test(`Org-Umzug: ${label} wird abgewiesen`, async t => {
  const f = fixture(t); mutate(f);
  await assert.rejects(f.verify(extra), reason);
});

for (const platform of Object.keys(platformFiles)) test(`${platform}: old installer hash cannot differ from the complete approval inventory`, async t => {
  const f = fixture(t);
  f.manifest.artifacts.platforms[platform].sha256 = hash("different approved bytes");
  await assert.rejects(f.verify(), /installer hash differs/);
});

test("manifest bytes cannot change after separate digest approval", async t => {
  const f = fixture(t);
  await assert.rejects(f.verify({ manifestSha256: hash("different manifest") }), /approved manifest hash differs/);
  await assert.rejects(f.verify({ tag: "v1.2.4" }), /tag differs from approval/);
  await assert.rejects(f.verify({ repository: "attacker/scai-releases" }), /repository differs from approval/);
  await assert.rejects(f.verify({ releaseId: `${releaseId}0` }), /release ID differs from approval/);
});

for (const [name, mutate] of [
  ["modified payload", f => writeFileSync(join(f.dir, "SCAI_aarch64.app.tar.gz"), "changed bytes")],
  ["missing file", f => unlinkSync(join(f.dir, "latest.json"))],
  ["additional file", f => writeFileSync(join(f.dir, "extra.json"), "extra")],
  ["asset symlink", f => { unlinkSync(join(f.dir, "latest.json")); symlinkSync(join(f.dir, "scai.cdx.json"), join(f.dir, "latest.json")); }],
  ["asset hardlink", f => { unlinkSync(join(f.dir, "latest.json")); linkSync(join(f.dir, "scai.cdx.json"), join(f.dir, "latest.json")); }],
  ["directory instead of asset", f => { unlinkSync(join(f.dir, "latest.json")); mkdirSync(join(f.dir, "latest.json")); }],
]) test(`${name}: reject downloaded bytes`, async t => {
  const f = fixture(t); mutate(f);
  await assert.rejects(f.verify());
});

test("symlinked download root is rejected", async t => {
  const f = fixture(t); const link = join(f.root, "linked-assets"); symlinkSync(f.dir, link);
  await assert.rejects(f.verify({ assetDir: link }), /asset directory must not be a link/);
});

test("self-consistent attacker SHA256SUMS cannot authorize changed installers", async t => {
  const f = fixture(t);
  f.contents.set("SCAI_aarch64.app.tar.gz", Buffer.from("replacement installer"));
  writeFileSync(join(f.dir, "SCAI_aarch64.app.tar.gz"), f.contents.get("SCAI_aarch64.app.tar.gz"));
  writeFileSync(join(f.dir, "SHA256SUMS"), f.sums());
  const oldGate = spawnSync("/bin/bash", ["-c", "if command -v sha256sum >/dev/null; then sha256sum -c SHA256SUMS; else shasum -a 256 -c SHA256SUMS; fi"], { cwd: f.dir, encoding: "utf8", env: { PATH: "/usr/bin:/bin", LANG: "C" } });
  assert.equal(oldGate.status, 0, "old checksum-only gate really accepts these substituted bytes");
  await assert.rejects(f.verify(), /downloaded hash differs from approval/);
});

for (const [name, mutate] of [
  ["wrong eleven keys", f => { f.latest.platforms["wrong-platform"] = f.latest.platforms["darwin-aarch64"]; delete f.latest.platforms["darwin-aarch64"]; }],
  ["updater foreign tag", f => { f.latest.platforms["darwin-aarch64"].url = url("SCAI_aarch64.app.tar.gz").replace(tag, "v1.2.4"); }],
  ["updater stale source", f => { f.latest.source_sha = "b".repeat(40); }],
  ["updater wrong version", f => { f.latest.version = "1.2.2"; }],
  ["updater mismatched signature", f => { f.latest.platforms["darwin-aarch64"].signature = "different"; }],
  ["updater empty signature", f => { f.contents.set("SCAI_aarch64.app.tar.gz.sig", Buffer.from("\n")); f.latest.platforms["darwin-aarch64"].signature = ""; }],
]) test(`${name}: reject even when malformed latest bytes were hashed`, async t => {
  const f = fixture(t); mutate(f);
  f.contents.set("latest.json", Buffer.from(JSON.stringify(f.latest))); f.approve();
  await assert.rejects(f.verify());
});

for (const [name, line] of [
  ["traversal", `${hash("outside")}  ../outside\n`],
  ["checksum omitted", ""],
  ["checksum duplicate", null],
]) test(`${name}: unsafe checksum inventory is rejected before shell use`, async t => {
  const f = fixture(t);
  const original = f.contents.get("SHA256SUMS").toString();
  f.contents.set("SHA256SUMS", Buffer.from(line === null ? original + original.split("\n")[0] + "\n" : line));
  f.approve({ replaceSums: false });
  await assert.rejects(f.verify());
});

test("signing evidence must carry the authorized policy", async t => {
  const f = fixture(t);
  const name = `signing-evidence-${targets[0]}.json`;
  f.contents.set(name, Buffer.from(JSON.stringify({ status: "pass", platform: targets[0], distribution_policy: "legacy-v0.125" }))); f.approve();
  await assert.rejects(f.verify(), /signing evidence policy differs/);
});

test("fresh remote readback rejects asset replacement after byte verification", async t => {
  const f = fixture(t); await f.verify();
  f.release.assets[0].digest = `sha256:${hash("late replacement")}`;
  await assert.rejects(f.verify({ assetDir: undefined }), /remote digest differs/);
});

test("historical non-PASS manifests stay readable; PASS needs authorization", () => {
  const manifest = JSON.parse(readFileSync(new URL("../fleet/manifests/scai-candidate-2026-08-24.1.json", import.meta.url)));
  assert.deepEqual(validateManifest(manifest), []);
  delete manifest.supersession; manifest.status = "pass";
  assert.match(validateManifest(manifest).join("\n"), /PASS requires complete authorized_release/);
  for (const bad of [null, {}, { repository, tag: "v1.2.3\n", distribution_policy: "market-ready", assets: [] }]) assert.ok(validateReleaseAuthorization(bad).length > 0);
});

test("real CLI binds inputs and reports metadata-only separately from bytes", t => {
  const f = fixture(t);
  const manifestPath = join(f.root, "manifest.json"); const metadataPath = join(f.root, "release.json");
  const opts = f.options(); writeFileSync(manifestPath, opts.manifestBytes); writeFileSync(metadataPath, JSON.stringify(f.release));
  const script = fileURLToPath(new URL("./verify-approved-release.mjs", import.meta.url));
  const run = (digest, mode) => spawnSync(process.execPath, [script, manifestPath, digest, repository, tag, releaseId, metadataPath, mode], { encoding: "utf8", env: { PATH: "/usr/bin:/bin", LANG: "C" }, timeout: 10000 });
  const metadata = run(opts.manifestSha256, "--metadata-only");
  assert.equal(metadata.status, 0, metadata.stderr); assert.match(metadata.stdout, /remote-metadata-only/); assert.doesNotMatch(metadata.stdout, /approved-release-bytes/);
  const full = run(opts.manifestSha256, f.dir); assert.equal(full.status, 0, full.stderr); assert.match(full.stdout, /approved-release-bytes/);
  assert.equal(run(hash("different"), f.dir).status, 1);
});

const workflow = readFileSync(new URL("../.github/workflows/publish-approved.yml", import.meta.url), "utf8");
function workflowCommands(name) {
  const block = workflow.split(`      - name: ${name}\n`)[1]?.split("\n      - name:")[0];
  assert.ok(block, `real workflow step missing: ${name}`);
  return block.split("        run: |\n")[1].split("\n").filter(line => line.startsWith("          ")).map(line => line.slice(10)).join("\n");
}
const verifyCommands = workflowCommands("Draft, Bindung und sämtliche Asset-Digests verifizieren");
const publishCommands = workflowCommands("Geprüften Draft veröffentlichen");

for (const scenario of ["success", "legacy_approval", "wrong_policy", "changed_bytes", "late_digest", "initial_downgrade", "late_downgrade", "wrong_tag", "api_failure"]) test(`real publisher steps: ${scenario} cannot bypass approval`, t => {
  // legacy_approval: Freigabe vor dem Umzug (subunit-ai), Workflow danach (REPO=Subunit-UG).
  const f = scenario === "legacy_approval" ? fixture(t, "market-ready", { approval: LEGACY, updater: LEGACY, artifacts: LEGACY }) : fixture(t);
  if (scenario === "wrong_policy") f.release.body = f.release.body.replace("market-ready", "legacy-v0.125");
  if (scenario === "changed_bytes") {
    f.contents.set("SCAI_aarch64.app.tar.gz", Buffer.from("unapproved replacement"));
    writeFileSync(join(f.dir, "SCAI_aarch64.app.tar.gz"), f.contents.get("SCAI_aarch64.app.tar.gz"));
    writeFileSync(join(f.dir, "SHA256SUMS"), f.sums());
  }
  const manifestPath = join(f.root, "manifest.json"); const metadataPath = join(f.root, "release.json");
  const opts = f.options(); writeFileSync(manifestPath, opts.manifestBytes); writeFileSync(metadataPath, JSON.stringify(f.release));
  const bin = join(f.root, "bin"); mkdirSync(bin);
  const temp = join(f.root, "runner"); mkdirSync(temp);
  symlinkSync(process.execPath, join(bin, "node"));
  if (existsSync("/usr/bin/sha256sum")) symlinkSync("/usr/bin/sha256sum", join(bin, "sha256sum"));
  else writeFileSync(join(bin, "sha256sum"), '#!/bin/bash\nexec /usr/bin/shasum -a 256 "$@"\n', { mode: 0o755 });
  const log = join(f.root, "gh-calls.jsonl"); writeFileSync(log, "");
  const state = join(f.root, "gh-state.json"); writeFileSync(state, '{"api":0,"latest":0}');
  writeFileSync(join(bin, "gh"), `#!${process.execPath}
import { appendFileSync, copyFileSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
const args = process.argv.slice(2), env = process.env;
appendFileSync(env.FIXTURE_LOG, JSON.stringify(args) + "\\n");
const state = JSON.parse(readFileSync(env.FIXTURE_STATE)), release = JSON.parse(readFileSync(env.FIXTURE_RELEASE));
if (args[0] === "api") {
  if (args.length !== 2 || args[1] !== "repos/" + env.REPO + "/releases/tags/" + env.TAG) process.exit(98);
  if (env.FIXTURE_SCENARIO === "api_failure") process.exit(29);
  state.api += 1;
  if (state.api === 2 && env.FIXTURE_SCENARIO === "late_digest") release.assets[0].digest = "sha256:" + "b".repeat(64);
  console.log(JSON.stringify(release));
} else if (args[0] === "release" && args[1] === "view") {
  if (args.includes("tagName")) {
    state.latest += 1;
    console.log(env.FIXTURE_SCENARIO === "initial_downgrade" || (state.latest === 2 && env.FIXTURE_SCENARIO === "late_downgrade") ? "v1.2.4" : "v1.2.2");
  } else console.log(JSON.stringify({ isDraft: release.draft, body: release.body, isPrerelease: release.prerelease, assets: release.assets }));
} else if (args[0] === "release" && args[1] === "download") {
  const dest = args[args.indexOf("--dir") + 1];
  if (!dest.startsWith(env.RUNNER_TEMP + "/")) process.exit(98);
  for (const name of readdirSync(env.FIXTURE_ASSETS)) copyFileSync(join(env.FIXTURE_ASSETS, name), join(dest, name));
} else if (args[0] === "release" && args[1] === "edit") {
  console.log("fixture: publication replaced");
} else process.exit(98);
writeFileSync(env.FIXTURE_STATE, JSON.stringify(state));
`, { mode: 0o755 });
  // This is the real workflow body. Only gh is replaced; both validator CLIs,
  // both SemVer gates and sha256sum execute normally over owned tiny fixtures.
  const root = dirname(dirname(fileURLToPath(import.meta.url)));
  const result = spawnSync("/bin/bash", ["-c", `${verifyCommands}\ncd "$GATE_SOURCE_DIR"\n${publishCommands}`], {
    cwd: root, encoding: "utf8", timeout: 20000,
    env: { PATH: `${bin}:/usr/bin:/bin`, LANG: "C", REPO: repository, TAG: scenario === "wrong_tag" ? "v1.2.4" : tag,
      RELEASE_ID: releaseId, SOURCE_SHA: source, MANIFEST: manifestPath, EXPECTED_MANIFEST_SHA256: opts.manifestSha256,
      RUNNER_TEMP: temp, GATE_SOURCE_DIR: root, FIXTURE_SCENARIO: scenario, FIXTURE_LOG: log, FIXTURE_STATE: state,
      FIXTURE_RELEASE: metadataPath, FIXTURE_ASSETS: f.dir },
  });
  assert.ifError(result.error);
  const calls = readFileSync(log, "utf8").trim().split("\n").filter(Boolean).map(line => JSON.parse(line));
  const edits = calls.filter(args => args[0] === "release" && args[1] === "edit");
  if (scenario === "success" || scenario === "legacy_approval") {
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.equal(edits.length, 1);
    assert.match(result.stdout, /approved-release-bytes/);
    const counts = JSON.parse(readFileSync(state));
    assert.deepEqual(counts, { api: 2, latest: 2 });
    assert.ok(calls.findLastIndex(args => args[0] === "api") < calls.indexOf(edits[0]));
  } else {
    assert.notEqual(result.status, 0, result.stdout + result.stderr);
    assert.equal(edits.length, 0, "a rejected gate cannot reach even the fake publish");
    if (["wrong_policy", "wrong_tag", "api_failure", "initial_downgrade"].includes(scenario)) assert.equal(calls.filter(args => args[1] === "download").length, 0);
    if (scenario === "api_failure") assert.equal(result.status, 29);
    else {
      const reason = { wrong_policy: /Distribution-Policy: missing, duplicate or mismatched binding/,
        changed_bytes: /downloaded hash differs from approval/, late_digest: /remote digest differs or is missing/,
        initial_downgrade: /muss strikt neuer/, late_downgrade: /muss strikt neuer/, wrong_tag: /tag differs from approval/ }[scenario];
      assert.match(result.stdout + result.stderr, reason, "failure must belong to the intended gate, not fixture setup");
    }
    if (scenario.startsWith("late_")) {
      const counts = JSON.parse(readFileSync(state));
      assert.equal(counts.latest, 2, "late counterexample really reaches the final publish step");
      assert.equal(counts.api, scenario === "late_digest" ? 2 : 1);
      assert.match(result.stdout, /approved-release-bytes/);
    }
  }
});
