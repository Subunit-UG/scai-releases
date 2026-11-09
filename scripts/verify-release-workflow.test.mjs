import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve, dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { validatePublishWorkflow, validateReleaseWorkflow } from "./verify-release-workflow.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const fixture = readFileSync(join(ROOT, ".github/workflows/build-all.yml"), "utf8");
const publishFixture = readFileSync(join(ROOT, ".github/workflows/publish-approved.yml"), "utf8");
const contractPaths = readFileSync(join(ROOT, "fleet/release-contract.paths"), "utf8");

test("current release workflow is fail-closed", () => {
  assert.deepEqual(validateReleaseWorkflow(fixture), []);
});

test("build and publish share one non-cancelling release mutation lock", () => {
  const unlockedBuild = fixture.replace("group: scai-release-mutation", "group: build-only");
  assert.match(validateReleaseWorkflow(unlockedBuild).join("\n"), /shared non-cancelling concurrency lock/);

  const cancellingBuild = fixture.replace("cancel-in-progress: false", "cancel-in-progress: true");
  assert.match(validateReleaseWorkflow(cancellingBuild).join("\n"), /shared non-cancelling concurrency lock/);

  const unlockedPublish = publishFixture.replace("group: scai-release-mutation", "group: publish-only");
  assert.match(validatePublishWorkflow(unlockedPublish, contractPaths).join("\n"), /share the non-cancelling release mutation lock/);
});

test("build and publish reject prefix-only draft identity checks", () => {
  const unsafeBuild = fixture.replace('grep -Fxq "Source-SHA:', 'grep -Fq "Source-SHA:');
  assert.match(validateReleaseWorkflow(unsafeBuild).join("\n"), /match complete binding lines/);
  const unsafePublish = publishFixture.replace('grep -Fxq "Source-SHA:', 'grep -Fq "Source-SHA:');
  assert.match(validatePublishWorkflow(unsafePublish, contractPaths).join("\n"), /match complete binding lines/);
});

test("public release notes cannot carry the private source ref", () => {
  const leaking = fixture.replace("          Source-SHA: $SOURCE_SHA\n", "          Source-Ref: $SOURCE_REF\n          Source-SHA: $SOURCE_SHA\n");
  assert.notEqual(leaking, fixture);
  assert.ok(validateReleaseWorkflow(leaking).some((fehler) => /private source ref/.test(fehler)));
});

test("a public pre-build release is rejected", () => {
  const unsafe = fixture.replace("--draft \\", "--not-a-draft \\");
  assert.match(validateReleaseWorkflow(unsafe).join("\n"), /release must be created as a draft/);
});

test("a draft cannot be created before every signing secret exists", () => {
  const unsafe = fixture.replace("name: Release-Secret-Preflight", "name: Unchecked-Secrets");
  assert.match(validateReleaseWorkflow(unsafe).join("\n"), /release secrets must be checked before/);
});

test("a bound signing secret must also be required by the preflight", () => {
  const unsafe = fixture.replace("APPLE_ID APPLE_PASSWORD APPLE_TEAM_ID", "APPLE_PASSWORD APPLE_TEAM_ID");
  assert.match(validateReleaseWorkflow(unsafe).join("\n"), /preflight must require APPLE_ID/);
});

test("legacy accepts the historical unencrypted updater key but market-ready does not", () => {
  const legacyBase = fixture.match(/BASE_RELEASE_SECRETS=\(\s*([\s\S]*?)\s*\)/)?.[1] ?? "";
  const marketReady = fixture.match(/MARKET_READY_SECRETS=\(\s*([\s\S]*?)\s*\)/)?.[1] ?? "";
  assert.doesNotMatch(legacyBase, /TAURI_SIGNING_PRIVATE_KEY_PASSWORD/);
  assert.match(marketReady, /TAURI_SIGNING_PRIVATE_KEY_PASSWORD/);
});

test("a mutable action reference is rejected", () => {
  const unsafe = fixture.replace(/actions\/attest@[0-9a-f]{40}/, "actions/attest@v4");
  assert.match(validateReleaseWorkflow(unsafe).join("\n"), /action reference must be immutable/);

  const shorthand = `${fixture}\n      - uses: attacker/action@main\n`;
  assert.match(validateReleaseWorkflow(shorthand).join("\n"), /action reference must be immutable/);
});

test("exact-SHA checkouts cannot inherit Windows line-ending rewrites", () => {
  const autocrlf = fixture.replace("git -C src config core.autocrlf false", "git -C src config core.autocrlf true");
  assert.match(validateReleaseWorkflow(autocrlf).join("\n"), /disable platform line-ending rewrites/);

  const nativeEol = fixture.replace("git -C src config core.eol lf", "git -C src config core.eol native");
  assert.match(validateReleaseWorkflow(nativeEol).join("\n"), /pin LF worktree bytes/);
});

test("a release build that can stream private compiler output is rejected", () => {
  const unsafe = fixture.replace('run-confidential.sh" "tauri-build-$TARGET"', 'run-publicly.sh" "tauri-build-$TARGET"');
  assert.match(validateReleaseWorkflow(unsafe).join("\n"), /confidential runner/);
});

test("Windows packaging cannot collapse its frontend proof back into one opaque Tauri step", () => {
  const unsafe = fixture.replace('run-confidential.sh" "windows-vite-$TARGET"', 'run-publicly.sh" "windows-vite-$TARGET"');
  assert.match(validateReleaseWorkflow(unsafe).join("\n"), /Windows vite prepackage output must pass through the confidential runner/);

  const duplicateFrontend = fixture.replace(
    `BUILD_ARGS+=(--config '{"build":{"beforeBuildCommand":null}}')`,
    "echo frontend-will-run-again",
  );
  assert.match(validateReleaseWorkflow(duplicateFrontend).join("\n"), /disable only the already executed Tauri frontend hook/);
});

test("Windows native broker diagnostics cannot leak names or accept unchecked indices", () => {
  const publicRunner = fixture.replace("run-indexed-confidential.sh", "run-publicly.sh");
  assert.match(validateReleaseWorkflow(publicRunner).join("\n"), /fixed-size indexed confidential runner/);

  const variableSize = fixture.replace('"windows-native-broker-$TARGET" 37 npm run check:native-broker', '"windows-native-broker-$TARGET" "$UNTRUSTED_COUNT" npm run check:native-broker');
  assert.match(validateReleaseWorkflow(variableSize).join("\n"), /fixed-size indexed confidential runner/);
});

test("Windows plugin envelope diagnostics remain fixed-size and confidential", () => {
  const publicRunner = fixture.replace(
    '"windows-plugin-envelope-$TARGET" 18 npm run check:plugin-envelope',
    '"windows-plugin-envelope-$TARGET" "$UNTRUSTED_COUNT" npm run check:plugin-envelope',
  );
  assert.match(validateReleaseWorkflow(publicRunner).join("\n"), /plugin envelope failures must use the fixed-size indexed confidential runner/);
});

test("Windows release gates reject the superseded proof sizes", () => {
  const staleBroker = fixture.replace(
    '"windows-native-broker-$TARGET" 37 npm run check:native-broker',
    '"windows-native-broker-$TARGET" 33 npm run check:native-broker',
  );
  assert.match(validateReleaseWorkflow(staleBroker).join("\n"), /Windows native broker failures must use the fixed-size indexed confidential runner/);

  const staleEnvelope = fixture.replace(
    '"windows-plugin-envelope-$TARGET" 18 npm run check:plugin-envelope',
    '"windows-plugin-envelope-$TARGET" 14 npm run check:plugin-envelope',
  );
  assert.match(validateReleaseWorkflow(staleEnvelope).join("\n"), /plugin envelope failures must use the fixed-size indexed confidential runner/);
});

test("Windows ARM CXX flags cannot be converted into a fake Git installation path", () => {
  const unsafe = fixture.replace(
    "MSYS2_ENV_CONV_EXCL=CXXFLAGS_aarch64_pc_windows_msvc",
    "MSYS2_ENV_CONV_EXCL=",
  );
  assert.match(validateReleaseWorkflow(unsafe).join("\n"), /excluded from MSYS path conversion/);
});

test("a broad release upload cannot replace the explicit asset allowlist", () => {
  const unsafe = fixture.replace('upload-draft-assets.sh" "${ASSETS[@]}"', 'upload-draft-assets.sh" "$BUNDLE_ROOT"');
  assert.match(validateReleaseWorkflow(unsafe).join("\n"), /explicit release asset allowlist/);
});

test("no asset upload can bypass the bound-draft guard", () => {
  const unsafe = fixture.replace(
    'bash "$GITHUB_WORKSPACE/gate/scripts/upload-draft-assets.sh" "$EVIDENCE"',
    'gh release upload "$TAG" "$EVIDENCE" -R "$REPO" --clobber',
  );
  assert.match(validateReleaseWorkflow(unsafe).join("\n"), /every release asset upload|must not bypass/);
});

test("updater signatures cannot be treated as native platform signing", () => {
  const unsafe = fixture.replaceAll("Get-AuthenticodeSignature", "Get-UnverifiedSignature");
  assert.match(validateReleaseWorkflow(unsafe).join("\n"), /Windows Authenticode signature must be verified/);
});

test("automatic updater publication cannot run without explicit opt-in", () => {
  const unsafe = fixture.replace(
    'if [ "$PUBLISH_UPDATE" != "true" ]; then',
    'if false; then',
  );
  assert.match(validateReleaseWorkflow(unsafe).join("\n"), /explicit publish_update input/);
});

test("automatic updater publication cannot race past a newer source main", () => {
  const unsafe = fixture.replace('test "$REMOTE_MAIN" = "$SOURCE_SHA"', "echo unchecked-main");
  assert.match(validateReleaseWorkflow(unsafe).join("\n"), /source main to equal the built SHA/);
});

test("automatic updater publication requires the exact source tag", () => {
  const unsafe = fixture.replace('test "$REMOTE_TAG" = "$SOURCE_SHA"', "echo unchecked-tag");
  assert.match(validateReleaseWorkflow(unsafe).join("\n"), /source tag to equal the built SHA/);
});

test("automatic updater publication verifies all asset digests first", () => {
  const unsafe = fixture.replace(
    'gh release edit "$TAG" -R "$REPO" --draft=false --prerelease=false --latest',
    'echo publish-without-gate',
  );
  assert.match(validateReleaseWorkflow(unsafe).join("\n"), /after asset digest verification/);
});

test("automatic updater publication cannot bypass the SemVer downgrade gate", () => {
  const unsafe = fixture.replace(
    'node "$GITHUB_WORKSPACE/scripts/assert-semver-monotonic.mjs" "$LATEST_TAG" "$TAG"',
    "echo semver-gate-removed",
  );
  assert.match(validateReleaseWorkflow(unsafe).join("\n"), /SemVer downgrade gate/);
});

test("legacy compatibility cannot run without the exact risk acknowledgement", () => {
  const unsafe = fixture.replace(
    'COMPATIBILITY_ACKNOWLEDGEMENT" != "I_ACCEPT_GATEKEEPER_AND_SMARTSCREEN"',
    'COMPATIBILITY_ACKNOWLEDGEMENT" != "ACK_OPTIONAL"',
  );
  assert.match(validateReleaseWorkflow(unsafe).join("\n"), /exact risk acknowledgement/);
});

test("legacy macOS cannot silently accept an arbitrary signing identity", () => {
  const unsafe = fixture.replace('legacy-v0.125:"Apple Development:"*', "legacy-v0.125:*");
  assert.match(validateReleaseWorkflow(unsafe).join("\n"), /historical Apple Development identity/);
});

test("legacy Windows must measure and disclose missing Authenticode", () => {
  const unsafe = fixture.replace('.Status -ne "NotSigned"', '.Status -ne "Valid"');
  assert.match(validateReleaseWorkflow(unsafe).join("\n"), /prove that both artifacts are unsigned/);

  const dishonest = fixture.replace("authenticode_verified = $false", "authenticode_verified = $true");
  assert.match(validateReleaseWorkflow(dishonest).join("\n"), /state the missing native signature/);
});

test("current publication workflow is fail-closed", () => {
  assert.deepEqual(validatePublishWorkflow(publishFixture, contractPaths), []);
});

test("manual publication cannot omit approved policy and complete asset binding", () => {
  for (const [before, after] of [
    ['"$RELEASE_METADATA" --metadata-only', '"$RELEASE_METADATA" --unchecked'],
    ['"$RELEASE_METADATA" "$ASSET_DIR"', '"$RELEASE_METADATA" --metadata-only'],
    ['"$RELEASE_METADATA" "$ASSET_DIR"', '"$RELEASE_METADATA" "$ASSET_DIR" || true'],
    ['"$RELEASE_METADATA" --metadata-only', '"$RELEASE_METADATA" --metadata-only || true'],
    ['gh api "repos/$REPO/releases/tags/$TAG" > "$RELEASE_METADATA"', 'true'],
    ['MANIFEST: ${{ steps.gate.outputs.manifest }}', 'MANIFEST: unapproved.json'],
  ]) {
    const unsafe = publishFixture.replace(before, after);
    assert.notEqual(unsafe, publishFixture);
    assert.ok(validatePublishWorkflow(unsafe, contractPaths).length > 0);
  }
  const finalOnly = publishFixture.replace(/(node scripts\/verify-approved-release\.mjs[^\n]+ --metadata-only)(?![\s\S]*node scripts\/verify-approved-release\.mjs)/, 'true');
  assert.notEqual(finalOnly, publishFixture);
  assert.match(validatePublishWorkflow(finalOnly, contractPaths).join("\n"), /approved policy\/tag\/inventory/);
  const ignored = publishFixture.replace('name: Draft, Bindung und sämtliche Asset-Digests verifizieren', 'name: Draft, Bindung und sämtliche Asset-Digests verifizieren\n        continue-on-error: true');
  assert.match(validatePublishWorkflow(ignored, contractPaths).join("\n"), /cannot ignore a failed gate/);
});

test("publication without Fleet PASS is rejected", () => {
  const unsafe = publishFixture.replace('test "$(jq -r .status "$MANIFEST")" = "pass"', "echo unchecked-status");
  assert.match(validatePublishWorkflow(unsafe, contractPaths).join("\n"), /publication must require manifest PASS/);
});

test("publication rejects removing either SemVer downgrade gate", () => {
  const command = 'node scripts/assert-semver-monotonic.mjs "$LATEST_TAG" "$TAG"';
  const missingEarlyGate = publishFixture.replace(command, "echo early-semver-gate-removed");
  assert.match(validatePublishWorkflow(missingEarlyGate, contractPaths).join("\n"), /SemVer/);

  const lastIndex = publishFixture.lastIndexOf(command);
  const missingFinalGate = `${publishFixture.slice(0, lastIndex)}echo final-semver-gate-removed${publishFixture.slice(lastIndex + command.length)}`;
  assert.match(validatePublishWorkflow(missingFinalGate, contractPaths).join("\n"), /SemVer/);
});

test("publication runs SemVer gates before download and after digest verification", () => {
  const command = 'node scripts/assert-semver-monotonic.mjs "$LATEST_TAG" "$TAG"';
  const firstIndex = publishFixture.indexOf(command);
  const misplaced = publishFixture.replace(command, "echo early-semver-gate-moved")
    .replace("sha256sum -c SHA256SUMS", `sha256sum -c SHA256SUMS\n          ${command}`);
  assert.equal(firstIndex >= 0, true);
  assert.match(validatePublishWorkflow(misplaced, contractPaths).join("\n"), /before asset download/);
});

test("publication without the approved manifest digest is rejected", () => {
  const unsafe = publishFixture.replace('test "$ACTUAL_MANIFEST_SHA256" = "$EXPECTED_MANIFEST_SHA256"', "echo unchecked-manifest");
  assert.match(validatePublishWorkflow(unsafe, contractPaths).join("\n"), /approved manifest SHA-256/);
});

test("publication before asset verification is rejected", () => {
  const unsafe = publishFixture.replace('gh release edit "$TAG"', 'echo publish-removed "$TAG"')
    .replace("sha256sum -c SHA256SUMS", 'gh release edit "$TAG"\n          sha256sum -c SHA256SUMS');
  assert.match(validatePublishWorkflow(unsafe, contractPaths).join("\n"), /only after PASS and asset verification/);
});

test("publication contract covers the complete confidential execution chain", () => {
  const missingFleetGate = contractPaths.replace(".github/workflows/fleet-source-check.yml\n", "");
  assert.match(validatePublishWorkflow(publishFixture, missingFleetGate).join("\n"), /path inventory must exactly cover/);

  const unpinnedInventory = publishFixture.replace('git show "$CONTRACT_SHA:$CONTRACT_PATHS_FILE"', 'cp "$CONTRACT_PATHS_FILE"');
  assert.match(validatePublishWorkflow(unpinnedInventory, contractPaths).join("\n"), /pin the path inventory itself/);
});
