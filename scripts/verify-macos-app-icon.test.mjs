import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const VERIFIER = join(ROOT, "scripts/verify-macos-app-icon.py");
const BUILD = readFileSync(join(ROOT, ".github/workflows/build-all.yml"), "utf8");

const plist = (entries) => `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>${Object.entries(entries).map(([k, v]) => `<key>${k}</key><string>${v}</string>`).join("")}</dict></plist>`;

function fixture({ icons = ["icons/icon.icns", "icons/Assets.car"], info = { CFBundleIconName: "subunit-os", CFBundleIconFile: "icon.icns" },
  car = true, icns = true, carNames = ["subunit-os"], assetutilCode = 0 } = {}) {
  const root = mkdtempSync(join(tmpdir(), "scai-app-icon-"));
  const resources = join(root, "SCAI.app/Contents/Resources");
  mkdirSync(resources, { recursive: true });
  writeFileSync(join(root, "tauri.conf.json"), JSON.stringify({ bundle: { icon: icons } }));
  writeFileSync(join(root, "SCAI.app/Contents/Info.plist"), plist(info));
  if (car) writeFileSync(join(resources, "Assets.car"), "car");
  if (icns) writeFileSync(join(resources, "icon.icns"), "icns");
  const payload = JSON.stringify([{ AssetStorageVersion: "fixture" }, ...carNames.map((Name) => ({ AssetType: "Icon Image", Name }))]);
  const assetutil = join(root, "assetutil");
  writeFileSync(assetutil, `#!/bin/sh\ncat <<'JSON'\n${payload}\nJSON\nexit ${assetutilCode}\n`);
  chmodSync(assetutil, 0o755);
  return root;
}

function verify(root, assetutil = join(root, "assetutil")) {
  return spawnSync("python3", [VERIFIER, join(root, "tauri.conf.json"), join(root, "SCAI.app"), "--assetutil", assetutil], { encoding: "utf8" });
}

test("build step checks every macOS app before archive normalisation and upload", () => {
  const call = 'python3 "$GITHUB_WORKSPACE/gate/scripts/verify-macos-app-icon.py" src-tauri/tauri.conf.json "$MAC_APP"';
  const at = BUILD.indexOf(call);
  assert.notEqual(at, -1);
  assert.equal(BUILD.indexOf(call, at + 1), -1);
  assert.ok(BUILD.lastIndexOf('if [ -n "$MAC_ARCHIVE_LABEL" ]; then', at) > BUILD.lastIndexOf("npm run tauri build", at));
  assert.ok(at < BUILD.indexOf('mv "$APP_ARCHIVE" "$NORMALIZED_ARCHIVE"', at));
  assert.ok(at < BUILD.indexOf("upload-draft-assets.sh", at));
});

test("complete system icon is accepted", () => {
  const root = fixture();
  const result = verify(root);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /'subunit-os'/);
  rmSync(root, { recursive: true, force: true });
});

test("source without system icon keeps building", () => {
  const root = fixture({ icons: ["icons/icon.icns"], car: false });
  const result = verify(root);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /legacy icon only/);
  rmSync(root, { recursive: true, force: true });
});

for (const [label, options] of [
  ["Assets.car missing", { car: false }],
  ["CFBundleIconName missing", { info: { CFBundleIconFile: "icon.icns" } }],
  ["icns fallback missing", { icns: false }],
  ["icon name not in car", { carNames: ["other"] }],
  ["assetutil fails", { assetutilCode: 1 }],
  ["declared .icon without car", { icons: ["icons/icon.icns", "icons/SCAI.icon"], car: false }],
]) {
  test(`silent fallback fails closed: ${label}`, () => {
    const root = fixture(options);
    const result = verify(root);
    assert.equal(result.status, 1, result.stdout);
    assert.match(result.stderr, /^error: /);
    rmSync(root, { recursive: true, force: true });
  });
}

test("missing assetutil fails closed", () => {
  const root = fixture();
  unlinkSync(join(root, "assetutil"));
  const result = verify(root);
  assert.equal(result.status, 1, result.stdout);
  rmSync(root, { recursive: true, force: true });
});
