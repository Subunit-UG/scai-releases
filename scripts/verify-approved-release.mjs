#!/usr/bin/env node
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { constants, closeSync, createReadStream, fstatSync, lstatSync, openSync, readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { validateManifest } from "./verify-fleet-manifest.mjs";
import { parseVersion } from "./assert-semver-monotonic.mjs";
import { releaseAssetUrl, sameReleaseAssetUrl, sameReleaseRepository, TARGETS, validateReleaseAuthorization } from "./release-authorization.mjs";

const sha256 = bytes => createHash("sha256").update(bytes).digest("hex");
const sameNames = (actual, expected, label) => assert.deepEqual([...actual].sort(), [...expected].sort(), `${label}: exact inventory required`);

function readSmallRegular(path) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(fd);
    assert.ok(stat.isFile() && stat.nlink === 1 && stat.size > 0 && stat.size <= 16 * 1024 * 1024, "metadata must be a bounded regular file, not a link");
    return readFileSync(fd);
  } finally { closeSync(fd); }
}

function verifyMetadata(manifest, release, repository, tag, releaseId) {
  const approved = manifest.authorized_release;
  assert.deepEqual(validateReleaseAuthorization(approved), [], "complete release authorization required");
  // Org-Umzug: Freigabe und Workflow dürfen je eine der zwei Schreibweisen desselben Repos tragen.
  assert.ok(sameReleaseRepository(approved.repository, repository), "repository differs from approval");
  assert.equal(approved.tag, tag, "tag differs from approval");
  assert.equal(manifest.release_id, releaseId, "release ID differs from approval");
  assert.equal(release.tag_name, tag, "draft lookup returned another tag");
  assert.equal(release.draft, true, "only an unpublished draft may be promoted");
  assert.equal(release.prerelease, parseVersion(tag).prerelease.length > 0, "prerelease state differs from approved tag");
  assert.equal(typeof release.body, "string", "missing release body");
  for (const [key, value] of [["Source-SHA", manifest.pins.scai_source.sha], ["Fleet-Release-ID", releaseId], ["Distribution-Policy", approved.distribution_policy]]) {
    const lines = release.body.split(/\r?\n/).filter(line => new RegExp(`^\\s*${key}\\s*:`).test(line));
    assert.deepEqual(lines, [`${key}: ${value}`], `${key}: missing, duplicate or mismatched binding`);
  }
  assert.ok(Array.isArray(release.assets), "remote asset inventory missing");
  sameNames(release.assets.map(asset => asset.name), approved.assets.map(asset => asset.name), "remote assets");
  const remote = new Map(release.assets.map(asset => [asset.name, asset]));
  for (const asset of approved.assets) {
    const found = remote.get(asset.name);
    assert.ok(sameReleaseAssetUrl(found.browser_download_url, asset.url), `remote URL differs: ${asset.name}`);
    assert.equal(found.digest, `sha256:${asset.sha256}`, `remote digest differs or is missing: ${asset.name}`);
    assert.equal(found.state, "uploaded", `remote asset incomplete: ${asset.name}`);
    assert.ok(Number.isSafeInteger(found.size) && found.size > 0, `invalid remote asset size: ${asset.name}`);
  }
  const assets = new Map(approved.assets.map(asset => [asset.name, asset]));
  const version = tag.slice(1);
  const platforms = {
    macos_arm64: [`SCAI_${version}_aarch64.dmg`, "SCAI_aarch64.app.tar.gz.sig", TARGETS[0]],
    macos_x64: [`SCAI_${version}_x64.dmg`, "SCAI_x64.app.tar.gz.sig", TARGETS[1]],
    windows_arm64: [`SCAI_${version}_arm64-setup.exe`, `SCAI_${version}_arm64-setup.exe.sig`, TARGETS[2]],
    windows_x64: [`SCAI_${version}_x64-setup.exe`, `SCAI_${version}_x64-setup.exe.sig`, TARGETS[3]],
    linux_x64: [`SCAI_${version}_amd64.AppImage`, `SCAI_${version}_amd64.AppImage.sig`, TARGETS[4]],
  };
  for (const [platform, [installer, signature, target]] of Object.entries(platforms)) {
    const record = manifest.artifacts.platforms[platform];
    assert.ok(sameReleaseAssetUrl(record.artifact_url, assets.get(installer).url), `${platform}: installer URL differs from approval`);
    assert.equal(record.sha256, assets.get(installer).sha256, `${platform}: installer hash differs from approval`);
    assert.ok(sameReleaseAssetUrl(record.updater_signature_url, assets.get(signature).url), `${platform}: signature URL differs from approval`);
    assert.ok(sameReleaseAssetUrl(record.sbom_url, assets.get("scai.cdx.json").url), `${platform}: SBOM URL differs from approval`);
    assert.equal(record.sbom_sha256, assets.get("scai.cdx.json").sha256, `${platform}: SBOM hash differs from approval`);
    if (platform !== "linux_x64") assert.ok(sameReleaseAssetUrl(record.code_signature_evidence_url, assets.get(`signing-evidence-${target}.json`).url), `${platform}: signing evidence URL differs from approval`);
  }
  return { approved, assets, remote };
}

async function hashRegularFile(path) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = fstatSync(fd, { bigint: true });
    assert.ok(before.isFile() && before.nlink === 1n && before.size > 0n, "release asset must be a nonempty regular file, not a link");
    const hash = createHash("sha256");
    for await (const chunk of createReadStream(path, { fd, autoClose: false })) hash.update(chunk);
    const after = fstatSync(fd, { bigint: true });
    const entry = lstatSync(path, { bigint: true });
    for (const key of ["dev", "ino", "size", "mtimeNs", "ctimeNs"]) {
      assert.equal(after[key], before[key], "asset changed during hashing");
      assert.equal(entry[key], before[key], "asset path changed during hashing");
    }
    assert.ok(entry.isFile(), "asset path is not a regular file");
    return { digest: hash.digest("hex"), size: Number(before.size) };
  } finally { closeSync(fd); }
}

export async function verifyApprovedRelease({ manifestBytes, manifestSha256, release, repository, tag, releaseId, assetDir }) {
  assert.match(manifestSha256, /^[0-9a-f]{64}$/);
  assert.equal(sha256(manifestBytes), manifestSha256, "approved manifest hash differs");
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  assert.deepEqual(validateManifest(manifest), [], "Fleet manifest must satisfy all existing gates");
  assert.equal(manifest.status, "pass", "only a PASS manifest can authorize publication");
  const { approved, assets, remote } = verifyMetadata(manifest, release, repository, tag, releaseId);
  if (assetDir === undefined) return { scope: "remote-metadata-only", assets: assets.size, policy: approved.distribution_policy };
  assert.ok(lstatSync(assetDir).isDirectory() && !lstatSync(assetDir).isSymbolicLink(), "asset directory must not be a link");
  sameNames(readdirSync(assetDir), assets.keys(), "downloaded assets");
  for (const asset of assets.values()) {
    const result = await hashRegularFile(join(assetDir, asset.name));
    assert.equal(result.digest, asset.sha256, `downloaded hash differs from approval: ${asset.name}`);
    assert.equal(result.size, remote.get(asset.name).size, `downloaded size differs: ${asset.name}`);
  }
  const text = name => {
    const bytes = readSmallRegular(join(assetDir, name));
    assert.equal(sha256(bytes), assets.get(name).sha256, `metadata changed after hashing: ${name}`);
    return bytes.toString("utf8");
  };
  const checksums = text("SHA256SUMS").trimEnd().split("\n").map(line => {
    const match = /^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._+-]*)$/.exec(line);
    assert.ok(match && !match[2].includes(".."), "unsafe or malformed checksum line");
    return { sha256: match[1], name: match[2] };
  });
  sameNames(checksums.map(entry => entry.name), [...assets.keys()].filter(name => name !== "SHA256SUMS"), "checksum entries");
  for (const entry of checksums) assert.equal(entry.sha256, assets.get(entry.name).sha256, "SHA256SUMS cannot authorize its own alternative bytes");
  const latest = JSON.parse(text("latest.json"));
  assert.equal(latest.version, tag.slice(1), "updater version differs");
  assert.equal(latest.source_sha, manifest.pins.scai_source.sha, "updater source differs");
  const version = tag.slice(1);
  const updater = {
    "darwin-aarch64": "SCAI_aarch64.app.tar.gz", "darwin-aarch64-app": "SCAI_aarch64.app.tar.gz",
    "darwin-x86_64": "SCAI_x64.app.tar.gz", "darwin-x86_64-app": "SCAI_x64.app.tar.gz",
    "windows-aarch64": `SCAI_${version}_arm64-setup.exe`, "windows-aarch64-nsis": `SCAI_${version}_arm64-setup.exe`,
    "windows-x86_64": `SCAI_${version}_x64-setup.exe`, "windows-x86_64-nsis": `SCAI_${version}_x64-setup.exe`,
    "linux-x86_64": `SCAI_${version}_amd64.AppImage`, "linux-x86_64-appimage": `SCAI_${version}_amd64.AppImage`, "linux-x86_64-deb": `SCAI_${version}_amd64.deb`,
  };
  sameNames(Object.keys(latest.platforms ?? {}), Object.keys(updater), "updater targets");
  for (const [key, name] of Object.entries(updater)) {
    assert.ok(sameReleaseAssetUrl(latest.platforms[key].url, releaseAssetUrl(repository, tag, name)), `${key}: wrong updater asset URL`);
    const signature = text(`${name}.sig`).trim();
    assert.ok(signature.length > 0, `${key}: empty signature`);
    assert.equal(latest.platforms[key].signature, signature, `${key}: updater signature differs from approved signature file`);
  }
  for (const target of TARGETS.slice(0, 4)) {
    const evidence = JSON.parse(text(`signing-evidence-${target}.json`));
    assert.equal(evidence.status, "pass", "signing evidence is not PASS");
    assert.equal(evidence.platform, target, "signing evidence target differs");
    assert.equal(evidence.distribution_policy, approved.distribution_policy, "signing evidence policy differs from approval");
  }
  return { scope: "approved-release-bytes", assets: assets.size, updaterTargets: Object.keys(updater).length, policy: approved.distribution_policy };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [manifestPath, manifestSha256, repository, tag, releaseId, metadataPath, mode, ...extra] = process.argv.slice(2);
    assert.ok(mode && extra.length === 0, "usage: verify-approved-release.mjs <manifest> <sha256> <repository> <tag> <release-id> <release-json> <asset-dir|--metadata-only>");
    const result = await verifyApprovedRelease({ manifestBytes: readSmallRegular(manifestPath), manifestSha256, repository, tag, releaseId,
      release: JSON.parse(readSmallRegular(metadataPath).toString("utf8")), assetDir: mode === "--metadata-only" ? undefined : mode });
    console.log(`PASS ${JSON.stringify(result)}`);
  } catch (error) {
    console.error(`FAIL approved release: ${error.message}`);
    process.exitCode = 1;
  }
}
