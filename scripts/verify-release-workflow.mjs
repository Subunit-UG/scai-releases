#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export const EXPECTED_RELEASE_CONTRACT_PATHS = [
  ".github/workflows/auth-pr-check.yml",
  ".github/workflows/build-all.yml",
  ".github/workflows/fleet-manifest.yml",
  ".github/workflows/fleet-source-check.yml",
  ".github/workflows/pr-check.yml",
  ".github/workflows/publish-approved.yml",
  ".github/workflows/windows-arm-smoke.yml",
  "fleet/evidence/market-attestation-template.json",
  "fleet/evidence/market-template.json",
  "fleet/evidence/operations-template.json",
  "fleet/manifest.schema.json",
  "fleet/release-contract.paths",
  "scripts/assert-semver-monotonic.mjs",
  "scripts/checkout-private-source.sh",
  "scripts/encrypt-confidential-log.mjs",
  "scripts/merge-cyclonedx.mjs",
  "scripts/release-authorization.mjs",
  "scripts/run-confidential.sh",
  "scripts/run-indexed-confidential.sh",
  "scripts/run-package-smoke.ps1",
  "scripts/run-package-smoke.sh",
  "scripts/setup-auth-ci-databases.sh",
  "scripts/upload-draft-assets.sh",
  "scripts/validate-private-source-ref.sh",
  "scripts/validate-release-assets.sh",
  "scripts/verify-approved-release.mjs",
  "scripts/verify-fleet-manifest.mjs",
  "scripts/verify-fleet-source-workflow.mjs",
  "scripts/verify-market-evidence-binding.mjs",
  "scripts/verify-readiness-evidence.mjs",
  "scripts/verify-release-workflow.mjs",
  "scripts/verify-revenue-proof-artifacts.mjs",
  "scripts/verify-runtime-evidence.mjs",
  "scripts/verify-source-confidentiality.mjs",
];

export function validateReleaseWorkflow(workflow) {
  const errors = [];
  const require = (condition, message) => { if (!condition) errors.push(message); };
  const has = (pattern) => pattern.test(workflow);

  require(!has(/grep -Fq "(?:Source-SHA|Fleet-Release-ID|Distribution-Policy):/), "draft identity checks must match complete binding lines");
  // Meet Windows ARM64: Objekt-Audit muss vor jedem Installer-Upload unabhängig geprüft werden.
  require(has(/id: meet-python\s*\n\s*uses: actions\/setup-python@[0-9a-f]{40}/), "Meet ARM64 audit needs a pinned Python setup");
  require(has(/if \[ "\$TARGET" = "aarch64-pc-windows-msvc" \]; then\s*\n[\s\S]{0,400}?verify-meet-arm64-audit\.py/), "Meet ARM64 audit verifier must run for the Windows ARM64 target");

  require(has(/source_sha:\s*\n(?:\s+.*\n){0,4}?\s+required:\s*true/m), "source_sha input must be required");
  require(has(/release_id:\s*\n(?:\s+.*\n){0,4}?\s+required:\s*true/m), "release_id input must be required");
  require(has(/distribution_policy:\s*\n[\s\S]{0,240}?- market-ready\s*\n\s*- legacy-v0\.125\s*\n\s*default:\s*market-ready/m), "distribution policy must default to market-ready and explicitly enumerate legacy-v0.125");
  require(has(/compatibility_acknowledgement:\s*\n[\s\S]{0,180}?default:\s*""/m), "legacy compatibility acknowledgement input must be explicit and empty by default");
  require(has(/concurrency:\s*\n\s*group:\s*scai-release-mutation\s*\n\s*cancel-in-progress:\s*false/m), "release mutations must use the shared non-cancelling concurrency lock");
  require(has(/publish_update:\s*\n[\s\S]{0,180}?type:\s*boolean[\s\S]{0,80}?default:\s*false/m), "automatic updater publication must be explicit and default off");
  require(has(/run-name:\s*SCAI \$\{\{ inputs\.ref \}\} · \$\{\{ inputs\.source_sha \}\}/), "release runs must expose their immutable source identity");
  const secretPreflightIndex = workflow.indexOf("name: Release-Secret-Preflight");
  const sourceCheckoutIndex = workflow.indexOf("name: Version aus dem Quell-Repo lesen");
  require(secretPreflightIndex >= 0 && sourceCheckoutIndex > secretPreflightIndex, "all release secrets must be checked before source checkout or draft creation");
  const secretPreflight = secretPreflightIndex >= 0 && sourceCheckoutIndex > secretPreflightIndex
    ? workflow.slice(secretPreflightIndex, sourceCheckoutIndex)
    : "";
  const baseSecretList = secretPreflight.match(/BASE_RELEASE_SECRETS=\(\s*([\s\S]*?)\s*\)/)?.[1] ?? "";
  const marketReadySecretList = secretPreflight.match(/MARKET_READY_SECRETS=\(\s*([\s\S]*?)\s*\)/)?.[1] ?? "";
  for (const name of [
    "SOURCE_DEPLOY_KEY",
    "TRACE_SOURCE_DEPLOY_KEY",
    "APPLE_CERTIFICATE",
    "APPLE_CERTIFICATE_PASSWORD",
    "APPLE_SIGNING_IDENTITY",
    "APPLE_ID",
    "APPLE_PASSWORD",
    "APPLE_TEAM_ID",
    "WINDOWS_CERTIFICATE",
    "WINDOWS_CERTIFICATE_PASSWORD",
    "WINDOWS_CERTIFICATE_SUBJECT",
    "TAURI_SIGNING_PRIVATE_KEY",
    "TAURI_SIGNING_PRIVATE_KEY_PASSWORD",
  ]) {
    require(secretPreflight.includes(`${name}: \${{ secrets.${name} }}`), `release secret preflight must bind ${name}`);
  }
  for (const name of [
    "SOURCE_DEPLOY_KEY",
    "TRACE_SOURCE_DEPLOY_KEY",
    "APPLE_CERTIFICATE",
    "APPLE_CERTIFICATE_PASSWORD",
    "APPLE_SIGNING_IDENTITY",
    "TAURI_SIGNING_PRIVATE_KEY",
  ]) require(new RegExp(`(^|\\s)${name}(\\s|$)`).test(baseSecretList), `base release secret preflight must require ${name}`);
  for (const name of [
    "APPLE_ID",
    "APPLE_PASSWORD",
    "APPLE_TEAM_ID",
    "WINDOWS_CERTIFICATE",
    "WINDOWS_CERTIFICATE_PASSWORD",
    "WINDOWS_CERTIFICATE_SUBJECT",
    "TAURI_SIGNING_PRIVATE_KEY_PASSWORD",
  ]) require(new RegExp(`(^|\\s)${name}(\\s|$)`).test(marketReadySecretList), `market-ready secret preflight must require ${name}`);
  require(has(/legacy-v0\.125\)[\s\S]{0,180}?COMPATIBILITY_ACKNOWLEDGEMENT" != "I_ACCEPT_GATEKEEPER_AND_SMARTSCREEN"/), "legacy-v0.125 must require the exact risk acknowledgement");
  require(has(/market-ready\)[\s\S]{0,160}?REQUIRED_RELEASE_SECRETS=\("\$\{BASE_RELEASE_SECRETS\[@\]\}" "\$\{MARKET_READY_SECRETS\[@\]\}"\)/), "market-ready must require base and native signing secrets");
  require(has(/legacy-v0\.125\)[\s\S]{0,320}?REQUIRED_RELEASE_SECRETS=\("\$\{BASE_RELEASE_SECRETS\[@\]\}"\)/), "legacy-v0.125 may require only the proven v0.125 base secrets");
  require(secretPreflight.includes('MISSING_RELEASE_SECRETS+=("$secret_name")'), "release secret preflight must fail closed on empty secrets");
  require((workflow.match(/git -C src fetch --depth 1 origin "\$SOURCE_SHA"/g) ?? []).length >= 2, "source checkout must fetch the immutable SHA in build and evidence jobs");
  require((workflow.match(/git -C src config core\.autocrlf false/g) ?? []).length === 3, "all exact-SHA source checkouts must disable platform line-ending rewrites");
  require((workflow.match(/git -C src config core\.eol lf/g) ?? []).length === 3, "all exact-SHA source checkouts must pin LF worktree bytes");
  require(!has(/git clone[^\n]*--branch/), "branch-based source checkout is forbidden");
  require(has(/gh release create "\$TAG"[\s\S]{0,200}?--draft/), "release must be created as a draft");
  require(!has(/uses:\s*tauri-apps\/tauri-action@/), "public release builds must not stream private compiler output through tauri-action");
  require(has(/run-confidential\.sh" "tauri-build-\$TARGET"/), "release build output must pass through the confidential runner");
  require(has(/SCAI_BUILD_SOURCE_SHA:\s*\$\{\{ needs\.release\.outputs\.source_sha \}\}/), "packaged binary must embed the immutable source SHA");
  require(has(/run-confidential\.sh" "package-runtime-\$TARGET"[\s\S]{0,240}?run-package-smoke\.sh/), "macOS/Linux package runtime smoke must stay confidential");
  require(has(/run-confidential\.sh" "package-runtime-\$TARGET"[\s\S]{0,240}?run-package-smoke\.ps1/), "Windows package runtime smoke must stay confidential");
  require(has(/verify-runtime-evidence\.mjs"[\s\\]*"\$EVIDENCE" "\$TARGET" "\$VERSION" "\$SOURCE_SHA"/), "every platform runtime evidence must be validated before upload");
  require(has(/runtime-evidence-\$TARGET\.json[\s\S]{0,240}?upload-draft-assets\.sh" "\$EVIDENCE"/), "only the validated runtime evidence file may be uploaded");
  require(has(/for target in aarch64-apple-darwin x86_64-apple-darwin aarch64-pc-windows-msvc x86_64-pc-windows-msvc x86_64-unknown-linux-gnu; do[\s\S]{0,320}?verify-runtime-evidence\.mjs/), "final manifest must revalidate runtime evidence for all five targets");
  for (const label of ["runtime", "typescript", "vite"]) {
    require(has(new RegExp(`run-confidential\\.sh" "windows-${label}-\\$TARGET"`)), `Windows ${label} prepackage output must pass through the confidential runner`);
  }
  require(has(/run-indexed-confidential\.sh"[\s\S]{0,100}?"windows-native-broker-\$TARGET" 37 npm run check:native-broker/), "Windows native broker failures must use the fixed-size indexed confidential runner");
  require(has(/run-indexed-confidential\.sh"[\s\S]{0,100}?"windows-plugin-envelope-\$TARGET" 18 npm run check:plugin-envelope/), "Windows plugin envelope failures must use the fixed-size indexed confidential runner");
  require(has(/CXXFLAGS_aarch64_pc_windows_msvc=\/EHsc[\s\S]{0,260}?MSYS2_ENV_CONV_EXCL=CXXFLAGS_aarch64_pc_windows_msvc/), "Windows ARM C++ exception flags must be excluded from MSYS path conversion");
  require(has(/RUNNER_OS:-}" = "Windows"[\s\S]{0,2400}?BUILD_ARGS\+=\(--config '\{"build":\{"beforeBuildCommand":null\}\}'\)/), "Windows prepackage proof must disable only the already executed Tauri frontend hook");
  require(has(/upload-draft-assets\.sh" "\$\{ASSETS\[@\]\}"/), "only the explicit release asset allowlist may be uploaded");
  require((workflow.match(/upload-draft-assets\.sh/g) ?? []).length === 4, "every release asset upload must pass through the bound-draft guard");
  require(!has(/gh release upload/), "workflow must not bypass the bound-draft upload guard");
  require(has(/IS_DRAFT=.*isDraft[\s\S]{0,500}?Source-SHA:/), "existing release reuse must verify draft state and source SHA");
  require(has(/needs:\s*\[release, build\][\s\S]{0,180}?needs\.build\.result == 'success'/), "evidence job must depend on successful release and build jobs");
  require(has(/Fleet-Release-ID: \$RELEASE_ID/), "draft must be bound to the Fleet release ID");
  require(has(/Distribution-Policy: \$DISTRIBUTION_POLICY/), "draft must be bound to the distribution policy");
  require(has(/if \[ "\$PUBLISH_UPDATE" != "true" \]; then[\s\S]{0,220}?exit 0/), "updater publication must require the explicit publish_update input");
  require(has(/REMOTE_MAIN=.*git ls-remote[\s\S]{0,520}?test "\$REMOTE_MAIN" = "\$SOURCE_SHA"/), "updater publication must require source main to equal the built SHA");
  require(has(/REMOTE_TAG=.*git ls-remote[\s\S]{0,520}?test "\$REMOTE_TAG" = "\$SOURCE_SHA"/), "updater publication must require the source tag to equal the built SHA");
  require(has(/\.version == \$version and \.source_sha == \$source_sha and \(\.platforms \| length\) == 11/), "updater publication must bind latest.json to version, source SHA and all targets");
  require(has(/sha256sum -c SHA256SUMS[\s\S]{0,420}?gh release edit "\$TAG"[^\n]*--draft=false --prerelease=false --latest/), "updater publication must happen only after asset digest verification");

  require(has(/Developer ID Application:/), "macOS must require Developer ID Application signing");
  require(has(/xcrun stapler validate/), "macOS notarization staple must be verified");
  require(has(/spctl --assess/), "macOS Gatekeeper acceptance must be verified");
  require(has(/Import-PfxCertificate/), "Windows signing certificate must be imported");
  require(has(/Get-AuthenticodeSignature/), "Windows Authenticode signature must be verified");
  require(has(/TimeStamperCertificate/), "Windows timestamp certificate must be verified");
  require(has(/legacy-v0\.125:"Apple Development:"\*/), "legacy macOS mode must require the historical Apple Development identity");
  require(has(/inputs\.distribution_policy == 'legacy-v0\.125'[\s\S]{0,1000}?\.Status -ne "NotSigned"/), "legacy Windows mode must prove that both artifacts are unsigned");
  require(has(/distribution_policy = "legacy-v0\.125"[\s\S]{0,180}?authenticode_verified = \$false[\s\S]{0,120}?timestamp_verified = \$false/), "legacy Windows evidence must state the missing native signature and timestamp");
  require(has(/distribution_policy": policy[\s\S]{0,500}?"gatekeeper_verified": gatekeeper == "true"[\s\S]{0,160}?"notarization_staple_verified": notarization == "true"/), "macOS evidence must record policy-specific Gatekeeper and notarization truth");
  require(has(/jedisct1\/minisign\/releases\/download\/0\.12\/minisign-0\.12-linux\.tar\.gz/), "Minisign verifier must come from a version-pinned upstream release");
  require(has(/9a599b48ba6eb7b1e80f12f36b94ceca7c00b7a5173c95c3efc88d9822957e73[\s\S]{0,100}?sha256sum -c -/), "Minisign verifier archive must pass its pinned SHA-256 before execution");
  require(has(/base64 --decode "\$signature" > "\$decoded_signature"[\s\S]{0,180}?"\$MINISIGN_BIN" -Vm "\$artifact" -x "\$decoded_signature"/), "Tauri's base64 signature envelope must be decoded before Minisign verification");
  require(has(/"\$SIG_COUNT" -ne 6/), "the updater signature set must contain exactly six artifacts");
  require(!has(/apt-get install[^\n]*minisign/), "Ubuntu package availability must not control updater signature verification");

  require(has(/@cyclonedx\/cyclonedx-npm@6\.0\.1/), "Node SBOM generator must be version pinned");
  require(has(/npm ls --prefix src[\s\S]{0,180}?NPM_LS_EXIT=\$\?/), "Node SBOM must inspect npm dependency problems before tolerating known peer conflicts");
  require(has(/\["react", "react-dom"\][\s\S]{0,640}?Unerwartete npm-Abhängigkeitsprobleme/), "Node SBOM may tolerate only the exact locked React peer-conflict set");
  require(has(/cyclonedx-npm --package-lock-only --ignore-npm-errors/), "CycloneDX may ignore npm errors only after the strict problem allowlist gate");
  require(has(/cargo install cargo-cyclonedx --version 0\.5\.9 --locked/), "Rust SBOM generator must be version and lock pinned");
  require(has(/merge-cyclonedx\.mjs/), "Node and Rust SBOMs must be merged");
  require((workflow.match(/uses:\s*actions\/attest@[0-9a-f]{40}/g) ?? []).length === 2, "provenance and SBOM need two immutable attest actions");
  require(has(/--predicate-type https:\/\/cyclonedx\.org\/bom/), "CycloneDX attestation must be independently verified");
  require(has(/gh attestation verify[\s\S]{0,300}?--source-digest "\$GITHUB_SHA"/), "attestation verification must bind the workflow source digest");

  for (const line of workflow.split("\n")) {
    const match = line.match(/^\s*(?:-\s*)?uses:\s*([^\s#]+)/);
    if (!match || match[1].startsWith("./")) continue;
    const ref = match[1].split("@").at(-1);
    require(/^[0-9a-f]{40}$/.test(ref ?? ""), `action reference must be immutable: ${match[1]}`);
  }

  const attestIndex = workflow.lastIndexOf("gh attestation verify");
  const draftGuardIndex = workflow.lastIndexOf('test "$(jq -r .isDraft');
  require(attestIndex >= 0 && draftGuardIndex > attestIndex, "draft state must be rechecked after independent attestation verification");
  const sourceMainIndex = workflow.lastIndexOf('test "$REMOTE_MAIN" = "$SOURCE_SHA"');
  const sourceTagIndex = workflow.lastIndexOf('test "$REMOTE_TAG" = "$SOURCE_SHA"');
  const updateDigestIndex = workflow.lastIndexOf("sha256sum -c SHA256SUMS");
  const updateSemverIndex = workflow.lastIndexOf('node "$GITHUB_WORKSPACE/scripts/assert-semver-monotonic.mjs" "$LATEST_TAG" "$TAG"');
  const updatePublishIndex = workflow.lastIndexOf('gh release edit "$TAG" -R "$REPO" --draft=false');
  require(
    sourceMainIndex > attestIndex
      && sourceTagIndex > sourceMainIndex
      && updateDigestIndex > sourceTagIndex
      && updateSemverIndex > updateDigestIndex
      && updatePublishIndex > updateSemverIndex,
    "automatic updater publication must follow attestations, exact source lineage, digest verification and the SemVer downgrade gate",
  );
  return errors;
}

export function validatePublishWorkflow(workflow, contractPaths) {
  const errors = [];
  const require = (condition, message) => { if (!condition) errors.push(message); };
  const has = (pattern) => pattern.test(workflow);

  require(!has(/grep -Fq "(?:Source-SHA|Fleet-Release-ID|Distribution-Policy):/), "publication identity checks must match complete binding lines");

  const actualContractPaths = contractPaths
    .split("\n")
    .map((path) => path.trim())
    .filter(Boolean);
  require(
    actualContractPaths.length === EXPECTED_RELEASE_CONTRACT_PATHS.length
      && actualContractPaths.every((path, index) => path === EXPECTED_RELEASE_CONTRACT_PATHS[index]),
    "release-contract path inventory must exactly cover every security-critical workflow and validator",
  );

  for (const input of ["release_id", "tag", "manifest_sha256"]) {
    require(has(new RegExp(`${input}:\\s*\\n(?:\\s+.*\\n){0,4}?\\s+required:\\s*true`, "m")), `${input} input must be required`);
  }
  require(has(/concurrency:\s*\n(?:\s*#.*\n)*\s*group:\s*scai-release-mutation\s*\n\s*cancel-in-progress:\s*false/m), "publication must share the non-cancelling release mutation lock");
  require(has(/test "\$GITHUB_REF" = "refs\/heads\/\$DEFAULT_BRANCH"/), "publication must run from the default branch");
  require(has(/node scripts\/verify-fleet-manifest\.mjs "\$MANIFEST"/), "publication must validate the Fleet manifest");
  require(has(/jq -r \.status "\$MANIFEST"[\s\S]{0,80}?= "pass"/), "publication must require manifest PASS");
  require(has(/sha256sum "\$MANIFEST"[\s\S]{0,160}?EXPECTED_MANIFEST_SHA256/), "publication must bind the approved manifest SHA-256");
  require(has(/git merge-base --is-ancestor "\$CONTRACT_SHA" "\$GITHUB_SHA"/), "publication must require an ancestor release-contract pin");
  require(has(/CONTRACT_PATHS_FILE=fleet\/release-contract\.paths/), "publication must load the release-contract path inventory");
  require(has(/git show "\$CONTRACT_SHA:\$CONTRACT_PATHS_FILE"[\s\S]{0,160}?cmp --silent/), "publication must pin the path inventory itself to the release contract");
  require(has(/git show "\$CONTRACT_SHA:\$path"[\s\S]{0,120}?cmp --silent/), "publication must reject release-contract drift");
  require(has(/Source-SHA: \$SOURCE_SHA/), "publication must bind the draft to the source SHA");
  require(has(/Fleet-Release-ID: \$RELEASE_ID/), "publication must bind the draft to the release ID");
  require(has(/sha256sum -c SHA256SUMS/), "publication must recheck all release asset digests");

  const semverCommand = 'node scripts/assert-semver-monotonic.mjs "$LATEST_TAG" "$TAG"';
  const semverIndexes = [];
  let semverIndex = workflow.indexOf(semverCommand);
  while (semverIndex >= 0) {
    semverIndexes.push(semverIndex);
    semverIndex = workflow.indexOf(semverCommand, semverIndex + semverCommand.length);
  }
  require(semverIndexes.length === 2, "publication must check SemVer monotonicity exactly twice");

  for (const line of workflow.split("\n")) {
    const match = line.match(/^\s*(?:-\s*)?uses:\s*([^\s#]+)/);
    if (!match || match[1].startsWith("./")) continue;
    const ref = match[1].split("@").at(-1);
    require(/^[0-9a-f]{40}$/.test(ref ?? ""), `action reference must be immutable: ${match[1]}`);
  }

  const passIndex = workflow.indexOf('= "pass"');
  const draftBindingIndex = workflow.indexOf('Fleet-Release-ID: $RELEASE_ID');
  const downloadIndex = workflow.indexOf('gh release download "$TAG"');
  const digestIndex = workflow.indexOf("sha256sum -c SHA256SUMS");
  const publishIndex = workflow.lastIndexOf('gh release edit "$TAG"');
  const approvalCommand = 'node scripts/verify-approved-release.mjs "$MANIFEST" "$EXPECTED_MANIFEST_SHA256" "$REPO" "$TAG" "$RELEASE_ID" "$RELEASE_METADATA"';
  const metadataGate = `${approvalCommand} --metadata-only`;
  const bytesGate = `${approvalCommand} "$ASSET_DIR"`;
  const metadataFirst = workflow.indexOf(metadataGate);
  const metadataLast = workflow.lastIndexOf(metadataGate);
  const bytesIndex = workflow.indexOf(bytesGate);
  const commandLines = workflow.split("\n").map(line => line.trim());
  require(commandLines.filter(line => line === metadataGate).length === 2
    && commandLines.filter(line => line === bytesGate).length === 1
    && metadataFirst > draftBindingIndex && metadataFirst < downloadIndex
    && bytesIndex > downloadIndex && bytesIndex < digestIndex
    && metadataLast > digestIndex && metadataLast < publishIndex,
  "publication must bind approved policy/tag/inventory before download, all approved bytes before checksums, and fresh remote digests immediately before publish");
  require((workflow.match(/gh api "repos\/\$REPO\/releases\/tags\/\$TAG" > "\$RELEASE_METADATA"/g) ?? []).length === 2,
    "publication must freshly read complete remote asset digests twice");
  require((workflow.match(/MANIFEST: \$\{\{ steps\.gate\.outputs\.manifest \}\}/g) ?? []).length === 2
    && (workflow.match(/EXPECTED_MANIFEST_SHA256: \$\{\{ inputs\.manifest_sha256 \}\}/g) ?? []).length === 3,
    "publication approval must use the originally hashed manifest in both steps");
  require(!/^\s*continue-on-error:/m.test(workflow), "publication steps cannot ignore a failed gate");
  require(passIndex >= 0 && digestIndex > passIndex && publishIndex > digestIndex, "publication must happen only after PASS and asset verification");
  require(
    semverIndexes.length === 2
      && semverIndexes[0] > draftBindingIndex
      && semverIndexes[0] < downloadIndex
      && semverIndexes[1] > digestIndex
      && semverIndexes[1] < publishIndex,
    "publication must reject SemVer downgrades before asset download and immediately before publish",
  );
  return errors;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const path = process.argv[2] ? resolve(process.argv[2]) : join(ROOT, ".github/workflows/build-all.yml");
  const publishPath = process.argv[3] ? resolve(process.argv[3]) : join(ROOT, ".github/workflows/publish-approved.yml");
  const contractPathsPath = process.argv[4] ? resolve(process.argv[4]) : join(ROOT, "fleet/release-contract.paths");
  const errors = [
    ...validateReleaseWorkflow(readFileSync(path, "utf8")).map((error) => `${path}: ${error}`),
    ...validatePublishWorkflow(readFileSync(publishPath, "utf8"), readFileSync(contractPathsPath, "utf8")).map((error) => `${publishPath}: ${error}`),
  ];
  if (errors.length) {
    for (const error of errors) console.error(`FAIL ${error}`);
    process.exit(1);
  }
  console.log(`PASS ${path} + ${publishPath} :: fail-closed build/publish split`);
}
