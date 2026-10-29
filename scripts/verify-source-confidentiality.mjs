#!/usr/bin/env node
import { createHash } from "node:crypto";
import { NATIVE_CLI_WORKFLOW } from "./native-cli-workflow-policy.mjs";
import { appendFileSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PRIVATE_POSTGRES_WORKFLOWS = ["auth-pr-check.yml", "atlas-pr-check.yml", "fleet-source-check.yml"];

// Also executed by the public-only preflight, before any job can receive a
// private key. No normalization: names/outputs must match the caller's request.
export function validatePrRequest(sourceSha, requestId, traceSha = "", traceBundleKey = "") {
  const sha = (value) => typeof value === "string" && value.length === 40 && /^[0-9a-f]{40}$/.test(value);
  if (!sha(sourceSha)) throw new Error("Exact lowercase 40-character source SHA required");
  if (typeof requestId !== "string" || requestId.length !== 36
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(requestId)) {
    throw new Error("Unique lowercase UUIDv4 request_id required");
  }
  if (traceSha !== "" && !sha(traceSha)) throw new Error("Optional Trace source must be an exact lowercase SHA");
  if (typeof traceBundleKey !== "string" || (traceBundleKey !== "" && traceSha === "")) {
    throw new Error("Trace bundle recipient requires an exact Trace source");
  }
  return { source_sha: sourceSha, request_id: requestId, trace_sha: traceSha };
}

// Deliberately closed grammar for the small security-critical job, rather than
// matching a safe-looking command inside comments or a skipped step. Changes to
// this contract must update the policy and its executable negative cases too.
const PR_PREFLIGHT = `  preflight:
    name: Exakten Source-Prüfauftrag ohne private Schlüssel validieren
    runs-on: ubuntu-latest
    permissions:
      contents: read
    outputs:
      source_sha: \${{ steps.request.outputs.source_sha }}
      request_id: \${{ steps.request.outputs.request_id }}
      trace_sha: \${{ steps.request.outputs.trace_sha }}
    steps:
      - name: Öffentlichen Confidential-Runner auschecken
        uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2, immutable
        with:
          path: gate
          persist-credentials: false
      - name: Source und Request fail-closed prüfen
        id: request
        shell: bash
        env:
          SOURCE_SHA: \${{ inputs.ref }}
          REQUEST_ID: \${{ inputs.request_id }}
          TRACE_SHA: \${{ inputs.trace_ref }}
          TRACE_BUNDLE_KEY: \${{ inputs.trace_bundle_public_key_base64 }}
        run: node gate/scripts/verify-source-confidentiality.mjs --pr-request`;

// Discover actual confidential producers rather than maintaining a list of known
// labels: a newly introduced wrapper must acquire the same end-to-end contract.
export function validatePrDiagnosticInventory(pr) {
  const errors = [];
  const require = (ok, message) => { if (!ok) errors.push(`pr-check.yml: diagnostic inventory: ${message}`); };
  const canonical = (text) => text.split("\n").filter(line => line.trim() && !line.trimStart().startsWith("#")).join("\n");
  const jobs = [...pr.matchAll(/^  ([\w-]+):\n([\s\S]*?)(?=^  [\w-]+:|$(?![\s\S]))/gm)];
  const directories = new Set();
  const artifactNames = [...pr.matchAll(/^          name: (.+)$/gm)].map(m => m[1]);
  let calls = 0;
  for (const [, job, body] of jobs) {
    const steps = [...body.matchAll(/^      - [\s\S]*?(?=^      - |$(?![\s\S]))/gm)].map(m => canonical(m[0]));
    // Fail closed before classifying uploads: quoted/aliased keys or values
    // must not hide an extra upload from the exact producer-consumer contract.
    for (const step of steps) {
      const first = step.split("\n")[0].match(/^      - (name|uses|id): (.+)$/);
      const entries = [...step.matchAll(/^        (\S.*)$/gm)].map(m => m[1]);
      const keys = entries.map(line => line.match(/^([A-Za-z_][A-Za-z0-9_-]*):(?: |$)/)?.[1]);
      if (first) keys.unshift(first[1]);
      require(Boolean(first) && keys.every(Boolean) && keys.length === new Set(keys).size,
        `${job}: all steps need canonical unique keys, without aliases or quoted mappings`);
      const uses = [...step.matchAll(/^(?:      - |        )uses: (.+)$/gm)].map(m => m[1]);
      require(uses.every(value => /^[A-Za-z0-9_./-]+@[a-zA-Z0-9_.-]+(?: #.*)?$/.test(value)),
        `${job}: action references must be canonical unquoted scalars`);
    }
    const producers = steps.filter(step => step.includes("run-confidential.sh"));
    if (!producers.length) continue;
    const ids = steps.flatMap(step => [...step.matchAll(/^        id: (.+)$/gm)].map(m => m[1]));
    const uploads = steps.filter(step => step.includes("uses: actions/upload-artifact@"));
    for (const upload of uploads) {
      const mapping = upload.match(/^        with:\n([\s\S]*?)(?=^        \S|$(?![\s\S]))/m)?.[1] ?? "";
      const entries = [...mapping.matchAll(/^          (\S.*)$/gm)].map(m => m[1]);
      const keys = entries.map(line => line.match(/^([A-Za-z_][A-Za-z0-9_-]*): /)?.[1]);
      const paths = entries.filter(line => line.startsWith("path: ")).map(line => line.slice(6));
      require(keys.length > 0 && keys.every(Boolean) && keys.length === new Set(keys).size
        && paths.length === 1 && /^\$\{\{ runner\.temp \}\}\/[A-Za-z0-9_.*\/-]+$/.test(paths[0])
        && !paths[0].includes("..") && !paths[0].includes("//"),
        `${job}: all artifact inputs need canonical unique mappings and one inline private path`);
    }
    const expectedDirectories = [];
    const claimedUploads = new Set();
    for (const step of producers) {
      const run = step.match(/^        run: ([\s\S]*?)(?=^        [\w-]+:|$(?![\s\S]))/m)?.[1] ?? "";
      const count = (run.match(/run-confidential\.sh/g) ?? []).length;
      calls += count;
      require(count > 0 && count === (step.match(/run-confidential\.sh/g) ?? []).length,
        `${job}: wrappers must be executable run commands, not comments or hidden mappings`);
      const id = step.match(/^        id: ([a-z][a-z0-9_]*)$/m)?.[1];
      require(Boolean(id) && ids.filter(value => value === id).length === 1,
        `${job}: every producer needs one unique step id`);
      const label = `${job}/${id ?? "missing-id"}`;
      const fields = [...step.matchAll(/^        ([\w-]+):/gm)].map(m => m[1]);
      require(fields.length === new Set(fields).size && fields.includes("env") && fields.includes("run")
        && !/^ {8,10}(?:["'][^"'\n]+["']\s*:|<<:)/m.test(step)
        && !run.includes("SCAI_ENCRYPTED_DIAGNOSTIC_"),
        `${label}: diagnostic mappings and runtime environment must not be shadowed`);
      require((step.match(/^          SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64:/gm) ?? []).length === 1
        && step.split("\n").includes("          SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64: ${{ inputs.diagnostic_public_key_base64 }}"),
        `${label}: recipient must cover every runtime branch`);
      const pathLines = [...step.matchAll(/^          SCAI_ENCRYPTED_DIAGNOSTIC_PATH: (.+)$/gm)];
      const directory = pathLines[0]?.[1].match(/^\$\{\{ inputs\.diagnostic_public_key_base64 != '' && format\('\{0\}\/([a-z0-9-]+)\/failure\.encrypted\.json', runner\.temp\) \|\| '' \}\}$/)?.[1];
      require(pathLines.length === 1 && Boolean(directory) && !directories.has(directory),
        `${label}: one exclusive private directory and encrypted destination required`);
      if (!directory) continue;
      directories.add(directory);
      expectedDirectories.push(directory);
      require(!/^        continue-on-error:/m.test(step), `${label}: producer failures must remain blocking`);
      const path = `          path: \${{ runner.temp }}/${directory}/*.encrypted.json`;
      const matches = uploads.filter(upload => upload.includes(path));
      require(matches.length === 1, `${label}: exactly one upload must retain every encrypted failure`);
      for (const upload of matches) {
        claimedUploads.add(upload);
        const name = upload.match(/^          name: (.+)$/m)?.[1];
        require(Boolean(name) && artifactNames.filter(value => value === name).length === 1
          && /^[a-z0-9-]+-(?:\$\{\{ matrix\.label \}\}-)?\$\{\{ github\.run_id \}\}$/.test(name)
          && (!/^    strategy:/m.test(body) || name.includes("${{ matrix.label }}")),
          `${label}: artifact must be unique across jobs and matrix entries`);
        const lines = upload.split("\n");
        require(lines.length === 8
          && /^      - name: .+$/.test(lines[0])
          && lines[1] === `        if: failure() && steps.${id}.outcome == 'failure' && inputs.diagnostic_public_key_base64 != ''`
          && lines[2] === "        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4, immutable"
          && lines[3] === "        with:"
          && lines[5] === path
          && lines[6] === "          if-no-files-found: error"
          && lines[7] === "          retention-days: 1"
          && steps.indexOf(upload) > steps.indexOf(step),
          `${label}: exact failed-step keyed immutable one-day upload required`);
      }
    }
    for (const upload of uploads) {
      if (claimedUploads.has(upload)) continue;
      // Existing visual envelopes keep their precise file paths. A directory,
      // multiline value, alias or wildcard cannot become an unclaimed upload.
      const path = upload.match(/^          path: (.+)$/m)?.[1] ?? "";
      require(/^\$\{\{ runner\.temp \}\}\/(?:scai-[a-z0-9-]+-encrypted-(?:shots|proof)\.json|trace-host-macos-arm64-internal\.tar\.gz\.envelope\.json)$/.test(path),
        `${job}: unbound or broad encrypted diagnostic upload forbidden`);
    }
    const setup = `      - name: Exklusive verschlüsselte Diagnoseordner vorbereiten
        if: inputs.diagnostic_public_key_base64 != ''
        shell: bash
        run: |
          set -euo pipefail
          umask 077\n${expectedDirectories.map(dir => `          mkdir "$RUNNER_TEMP/${dir}"`).join("\n")}`;
    require(steps.filter(step => step === setup).length === 1
      && steps.indexOf(setup) < steps.indexOf(producers[0]),
      `${job}: exclusive directories must be created privately before any producer`);
  }
  require(calls > 0 && calls === (pr.match(/run-confidential\.sh/g) ?? []).length,
    "every actual wrapper must belong to an inventoried canonical job and step");
  return errors;
}

function requirePrContract(pr, require) {
  const canonical = (text) => text.split("\n").filter((line) => line.trim() && !line.trimStart().startsWith("#")).join("\n");
  const roots = [...pr.matchAll(/^([\w-]+):/gm)].map((match) => match[1]);
  require(JSON.stringify(roots) === JSON.stringify(["name", "run-name", "on", "permissions", "concurrency", "jobs"])
    && privateServiceOptions(pr) !== null, "pr-check.yml: request contract needs canonical unique workflow/job mappings, no global env or aliases");
  require(/^run-name: SCAI PR · \$\{\{ inputs\.ref \}\} · \$\{\{ inputs\.request_id \}\}$/m.test(pr),
    "pr-check.yml: run name must bind exact private source ref and request_id");
  for (const key of ["ref", "request_id"]) {
    const blocks = [...pr.matchAll(new RegExp(`^      ${key}:\\n([\\s\\S]*?)(?=^      [\\w-]+:|^\\S|$(?![\\s\\S]))`, "gm"))];
    const body = blocks[0]?.[1] ?? "";
    const fields = [...body.matchAll(/^        ([\w-]+):/gm)].map((m) => m[1]);
    require(blocks.length === 1 && /^        required: true$/m.test(body) && /^        type: string$/m.test(body)
      && JSON.stringify(fields) === JSON.stringify(["description", "required", "type"]),
    `pr-check.yml: ${key} must be a required string without default`);
  }
  const concurrency = pr.match(/^concurrency:\n([\s\S]*?)(?=^\S)/m)?.[1] ?? "";
  require(canonical(concurrency) === '  group: pr-check-${{ inputs.ref }}-${{ inputs.request_id }}\n  cancel-in-progress: false',
    "pr-check.yml: concurrency must bind source/request without cancelling another proof");

  const jobs = [...pr.slice(pr.indexOf("\njobs:\n") + 1).matchAll(/^  ([\w-]+):\n([\s\S]*?)(?=^  [\w-]+:|$(?![\s\S]))/gm)];
  require(JSON.stringify(jobs.map((job) => job[1])) === JSON.stringify(["preflight", "check", "trace-standalone", "native-trace"]),
    "pr-check.yml: all private jobs must stay in the explicit preflight dependency graph");
  require(canonical(jobs[0]?.[0] ?? "") === PR_PREFLIGHT, "pr-check.yml: preflight must validate inputs without secrets, private checkout or bypass");
  for (const [ , name, body] of jobs.slice(1)) {
    const header = body.split(/^    steps:\s*$/m)[0];
    const condition = name === "trace-standalone"
      ? "    if: inputs.trace_ref != '' && needs.preflight.result == 'success'"
      : "    if: needs.preflight.result == 'success'";
    require(/^    needs: preflight$/m.test(header) && header.split("\n").includes(condition)
      && !/^    (continue-on-error|env|defaults|services):/m.test(header),
    `pr-check.yml: ${name} must require successful preflight without job-level bypass`);
    const checkout = body.match(/      - name: (?:Quellcode auschecken|Exakten privaten Trace-Stand auschecken)[\s\S]*?(?=\n      - (?:name:|uses:))/)?.[0] ?? "";
    const output = name === "trace-standalone" ? "trace_sha" : "source_sha";
    require(checkout.includes(`          SRC_REF: \${{ needs.preflight.outputs.${output} }}`)
      && checkout.includes('          REQUEST_ID: ${{ needs.preflight.outputs.request_id }}'),
    `pr-check.yml: ${name} checkout must consume validated source/request outputs`);
  }

  const check = jobs.find((job) => job[1] === "check")?.[2] ?? "";
  const steps = [...check.matchAll(/^      - (?:name:|uses:)[\s\S]*?(?=^      - (?:name:|uses:)|$(?![\s\S]))/gm)].map((m) => canonical(m[0]));
  const rustSetup = `      - name: Rust für compilerführende Frontendtests einrichten
        uses: dtolnay/rust-toolchain@4360b52568e2003a75bf9bc1d59f33a8e3fc893c # stable, immutable
        timeout-minutes: 5`;
  const rustReady = `      - name: Rust-Compiler vor privaten Tests prüfen
        shell: bash
        timeout-minutes: 2
        run: rustc --version --verbose`;
  const privateCheckout = steps.findIndex((step) => step.startsWith("      - name: Quellcode auschecken ("));
  const frontendTests = steps.findIndex((step) => step.startsWith("      - name: Frontend-Vertragstests ausführen\n"));
  const rustSteps = steps.filter((step) => step.includes("uses: dtolnay/rust-toolchain@"));
  require(rustSteps.length === 1 && rustSteps[0] === rustSetup
    && steps.filter((step) => step === rustReady).length === 1
    && steps.indexOf(rustSetup) < steps.indexOf(rustReady)
    && steps.indexOf(rustReady) < privateCheckout && steps.indexOf(rustReady) < frontendTests,
  "pr-check.yml: Rust setup and bounded compiler readiness must precede private checkout and frontend tests without bypass");
  const pluginDeploy = `      - name: Plugin-Deploy-Snapshot und Fehlergrenzen prüfen
        id: plugin_deploy_tests
        working-directory: src
        shell: bash
        env:
          SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64: \${{ inputs.diagnostic_public_key_base64 }}
          SCAI_ENCRYPTED_DIAGNOSTIC_PATH: \${{ inputs.diagnostic_public_key_base64 != '' && format('{0}/scai-plugin-deploy-tests-diagnostic/failure.encrypted.json', runner.temp) || '' }}
        run: bash "$GITHUB_WORKSPACE/gate/scripts/run-confidential.sh" plugin-deploy-tests npm run test:plugin-deploy`;
  require(steps.filter(step => step === pluginDeploy).length === 1,
    "pr-check.yml: plugin-deploy-tests must be an unconditional confidential fail-closed source gate");
  const webReleaseFixture = `      - name: Web- und Release-Fixture-Verträge prüfen
        id: web_release_fixture_tests
        working-directory: src
        shell: bash
        env:
          SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64: \${{ inputs.diagnostic_public_key_base64 }}
          SCAI_ENCRYPTED_DIAGNOSTIC_PATH: \${{ inputs.diagnostic_public_key_base64 != '' && format('{0}/scai-web-release-fixture-diagnostic/failure.encrypted.json', runner.temp) || '' }}
        run: bash "$GITHUB_WORKSPACE/gate/scripts/run-confidential.sh" web-release-fixture-tests npm run test:web`;
  require(steps.filter((step) => step === webReleaseFixture).length === 1
    && steps.filter((step) => /^        id: web_release_fixture_tests$/m.test(step)).length === 1,
    "pr-check.yml: Web/release fixture diagnostics require exact mandatory confidential keyed source gate");
  const webReleaseFixtureUploads = steps.filter((step) => step.includes("uses: actions/upload-artifact@") && step.includes("scai-web-release-fixture"));
  require(webReleaseFixtureUploads.length === 1 && webReleaseFixtureUploads[0] === `      - name: Verschlüsselte Web-/Release-Fixture-Fehlerdiagnostik bereitstellen
        if: failure() && steps.web_release_fixture_tests.outcome == 'failure' && inputs.diagnostic_public_key_base64 != ''
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4, immutable
        with:
          name: scai-web-release-fixture-encrypted-diagnostic-\${{ github.run_id }}
          path: \${{ runner.temp }}/scai-web-release-fixture-diagnostic/*.encrypted.json
          if-no-files-found: error
          retention-days: 1`,
    "pr-check.yml: Web/release fixture diagnostics require exact failed step one-day encrypted envelope");
  const frontendUnit = `      - name: Frontend-Vertragstests ausführen
        id: frontend_unit_tests
        working-directory: src
        shell: bash
        env:
          SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64: \${{ inputs.diagnostic_public_key_base64 }}
          SCAI_ENCRYPTED_DIAGNOSTIC_PATH: \${{ inputs.diagnostic_public_key_base64 != '' && format('{0}/scai-frontend-unit-diagnostic/failure.encrypted.json', runner.temp) || '' }}
        run: bash "$GITHUB_WORKSPACE/gate/scripts/run-confidential.sh" frontend-unit-tests bun test src/lib`;
  require(steps.filter((step) => step === frontendUnit).length === 1,
    "pr-check.yml: Frontend unit diagnostics must stay confidential and use the supplied one-time key");
  const frontendUnitUploads = steps.filter((step) => step.includes("uses: actions/upload-artifact@") && step.includes("scai-frontend-unit"));
  require(frontendUnitUploads.length === 1 && frontendUnitUploads[0] === `      - name: Verschlüsselte Frontend-Vertragstest-Fehlerdiagnostik bereitstellen
        if: failure() && steps.frontend_unit_tests.outcome == 'failure' && inputs.diagnostic_public_key_base64 != ''
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4, immutable
        with:
          name: scai-frontend-unit-encrypted-diagnostic-\${{ github.run_id }}
          path: \${{ runner.temp }}/scai-frontend-unit-diagnostic/*.encrypted.json
          if-no-files-found: error
          retention-days: 1`, "pr-check.yml: Frontend unit diagnostics may upload only the keyed one-day encrypted envelope, never raw test output");
  const frontendBuild = `      - name: Bauen (tsc + vite)
        id: frontend_build
        working-directory: src
        shell: bash
        env:
          SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64: \${{ inputs.diagnostic_public_key_base64 }}
          SCAI_ENCRYPTED_DIAGNOSTIC_PATH: \${{ inputs.diagnostic_public_key_base64 != '' && format('{0}/scai-frontend-build-diagnostic/failure.encrypted.json', runner.temp) || '' }}
        run: bash "$GITHUB_WORKSPACE/gate/scripts/run-confidential.sh" frontend-build npm run build`;
  require(steps.filter(step => step === frontendBuild).length === 1
    && steps.filter(step => /^        id: frontend_build$/m.test(step)).length === 1,
    "pr-check.yml: Frontend build diagnostics require exact mandatory confidential keyed gate");
  const frontendBuildUploads = steps.filter(step => step.includes("uses: actions/upload-artifact@") && step.includes("scai-frontend-build"));
  require(frontendBuildUploads.length === 1 && frontendBuildUploads[0] === `      - name: Verschlüsselte Frontend-Build-Fehlerdiagnostik bereitstellen
        if: failure() && steps.frontend_build.outcome == 'failure' && inputs.diagnostic_public_key_base64 != ''
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4, immutable
        with:
          name: scai-frontend-build-encrypted-diagnostic-\${{ github.run_id }}
          path: \${{ runner.temp }}/scai-frontend-build-diagnostic/*.encrypted.json
          if-no-files-found: error
          retention-days: 1`,
    "pr-check.yml: Frontend build diagnostics require exact failed step one-day encrypted envelope");
  const cargoTest = `      - name: cargo test (Sidecar-Trust-Modell + Takoru + verify-Suite)
        id: cargo_test
        working-directory: src
        shell: bash
        env:
          SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64: \${{ inputs.diagnostic_public_key_base64 }}
          SCAI_ENCRYPTED_DIAGNOSTIC_PATH: \${{ inputs.diagnostic_public_key_base64 != '' && format('{0}/scai-cargo-test-diagnostic/failure.encrypted.json', runner.temp) || '' }}
        run: bash "$GITHUB_WORKSPACE/gate/scripts/run-confidential.sh" cargo-test cargo test --manifest-path src-tauri/Cargo.toml --lib --features local-meet`;
  require(steps.filter(step => step === cargoTest).length === 1
    && steps.filter(step => /^        id: cargo_test$/m.test(step)).length === 1,
    "pr-check.yml: Cargo test diagnostics require exact mandatory confidential keyed gate");
  const cargoTestUploads = steps.filter(step => step.includes("uses: actions/upload-artifact@") && step.includes("scai-cargo-test"));
  require(cargoTestUploads.length === 1 && cargoTestUploads[0] === `      - name: Verschlüsselte Cargo-Test-Fehlerdiagnostik bereitstellen
        if: failure() && steps.cargo_test.outcome == 'failure' && inputs.diagnostic_public_key_base64 != ''
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4, immutable
        with:
          name: scai-cargo-test-encrypted-diagnostic-\${{ github.run_id }}
          path: \${{ runner.temp }}/scai-cargo-test-diagnostic/*.encrypted.json
          if-no-files-found: error
          retention-days: 1`,
    "pr-check.yml: Cargo test diagnostics require exact failed step one-day encrypted envelope");
  const webkit = `      - name: Host-Restore explizit mit WebKit beweisen
        id: host_restore_webkit
        working-directory: src
        shell: bash
        env:
          PAGES_PROOF_BROWSER: webkit
          PAGES_PROOF_FOCUS: host-restore
          PAGES_PROOF_OUT: \${{ runner.temp }}/scai-host-restore-webkit
          SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64: \${{ inputs.diagnostic_public_key_base64 }}
          SCAI_ENCRYPTED_DIAGNOSTIC_PATH: \${{ inputs.diagnostic_public_key_base64 != '' && format('{0}/scai-host-restore-webkit-diagnostic/failure.encrypted.json', runner.temp) || '' }}
        run: bash "$GITHUB_WORKSPACE/gate/scripts/run-confidential.sh" host-restore-webkit-proof node scripts/verify-pages-foundation.mjs`;
  require(steps.filter((step) => step === webkit).length === 1, "pr-check.yml: WebKit host restore must retain its explicit confidential unfiltered source gate");
  const install = steps.indexOf(`      - name: Browser für Seh-Harnesse
        id: playwright_install
        working-directory: src
        shell: bash
        env:
          SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64: \${{ inputs.diagnostic_public_key_base64 }}
          SCAI_ENCRYPTED_DIAGNOSTIC_PATH: \${{ inputs.diagnostic_public_key_base64 != '' && format('{0}/scai-playwright-install-diagnostic/failure.encrypted.json', runner.temp) || '' }}
        run: bash "$GITHUB_WORKSPACE/gate/scripts/run-confidential.sh" playwright-install npx playwright install --with-deps chromium webkit`);
  require(install >= 0 && install < steps.indexOf(webkit), "pr-check.yml: WebKit system dependencies must precede host restore");
  const webkitUploads = steps.filter((step) => step.includes("uses: actions/upload-artifact@") && /host.restore.webkit/.test(step));
  require(webkitUploads.length === 1 && webkitUploads[0] === `      - name: Verschlüsselte WebKit-Host-Restore-Fehlerdiagnostik bereitstellen
        if: failure() && steps.host_restore_webkit.outcome == 'failure' && inputs.diagnostic_public_key_base64 != ''
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4, immutable
        with:
          name: scai-host-restore-webkit-encrypted-diagnostic-\${{ github.run_id }}
          path: \${{ runner.temp }}/scai-host-restore-webkit-diagnostic/*.encrypted.json
          if-no-files-found: error
          retention-days: 1`, "pr-check.yml: WebKit diagnostics must be only the keyed one-day encrypted envelope, never raw proof output");
}

function privateServiceOptions(workflow) {
  const lines = workflow.split("\n");
  const indent = (line) => line.match(/^ */)?.[0].length ?? 0;
  const significant = (line) => Boolean(line.trim()) && !line.trimStart().startsWith("#");
  const scalarMarker = (value) => /^(?:[>|][-+]?)(?:\s+#.*)?$/.test(value);
  const cleanValue = (value) => value.replace(/\s+#.*$/, "").trim();
  const forbiddenValueForm = (value) => /^[{[*&]/.test(cleanValue(value));
  const skippedScalarLines = new Set();

  // Shell embedded in run: block scalars is data, even when it happens to look
  // like a mapping key at one of the policy-controlled indentation levels.
  for (let index = 0; index < lines.length; index += 1) {
    const scalar = lines[index].match(/^( *)(?:-\s+)?[A-Za-z_][A-Za-z0-9_-]*:\s*([>|][-+]?)\s*(?:#.*)?$/);
    if (!scalar) continue;
    const baseIndent = scalar[1].length;
    for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
      if (significant(lines[cursor]) && indent(lines[cursor]) <= baseIndent) break;
      skippedScalarLines.add(cursor);
    }
  }

  const entryAt = (index, expectedIndent) => {
    if (skippedScalarLines.has(index) || !significant(lines[index]) || indent(lines[index]) !== expectedIndent) return undefined;
    const match = lines[index].match(new RegExp(`^ {${expectedIndent}}([A-Za-z_][A-Za-z0-9_-]*):(.*)$`));
    if (!match || (match[2] && !match[2].startsWith(" "))) return null;
    return { key: match[1], value: match[2] };
  };
  const blockEnd = (start, parentIndent, limit = lines.length) => {
    let cursor = start;
    while (cursor < limit) {
      if (!skippedScalarLines.has(cursor) && significant(lines[cursor]) && indent(lines[cursor]) <= parentIndent) break;
      cursor += 1;
    }
    return cursor;
  };
  const emptyMappingValue = (value) => cleanValue(value) === "";
  const unique = (seen, key) => {
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  };
  const services = [];
  let valid = true;
  let jobsCount = 0;
  const rootKeys = new Set();

  const nextSignificant = (start, limit) => {
    let cursor = start;
    while (cursor < limit && (skippedScalarLines.has(cursor) || !significant(lines[cursor]))) cursor += 1;
    return cursor;
  };

  const parseServices = (start, limit) => {
    const serviceNames = new Set();
    for (let cursor = nextSignificant(start, limit); cursor < limit; cursor = nextSignificant(cursor, limit)) {
      if (indent(lines[cursor]) !== 6) {
        valid = false;
        cursor += 1;
        continue;
      }
      const service = entryAt(cursor, 6);
      if (service === null || !emptyMappingValue(service.value) || !unique(serviceNames, service.key)) {
        valid = false;
        cursor += 1;
        continue;
      }
      const serviceEnd = blockEnd(cursor + 1, 6, limit);
      const attributeNames = new Set();
      const optionFields = [];
      for (let attributeIndex = nextSignificant(cursor + 1, serviceEnd); attributeIndex < serviceEnd; attributeIndex = nextSignificant(attributeIndex, serviceEnd)) {
        if (indent(lines[attributeIndex]) !== 8) {
          valid = false;
          attributeIndex += 1;
          continue;
        }
        const attribute = entryAt(attributeIndex, 8);
        if (attribute === null || !unique(attributeNames, attribute.key) || forbiddenValueForm(attribute.value)) {
          valid = false;
          attributeIndex += 1;
          continue;
        }
        const attributeEnd = blockEnd(attributeIndex + 1, 8, serviceEnd);
        if (attribute.key === "options") {
          const value = cleanValue(attribute.value);
          if (!scalarMarker(value)) {
            valid = false;
          } else {
            const parts = [];
            for (let valueIndex = attributeIndex + 1; valueIndex < attributeEnd; valueIndex += 1) {
              if (significant(lines[valueIndex])) parts.push(lines[valueIndex].trim());
            }
            optionFields.push(parts);
          }
        }
        attributeIndex = attributeEnd;
      }
      services.push({ name: service.key, optionFields });
      cursor = serviceEnd;
    }
  };

  const parseJobs = (start, limit) => {
    const jobNames = new Set();
    for (let cursor = nextSignificant(start, limit); cursor < limit; cursor = nextSignificant(cursor, limit)) {
      if (indent(lines[cursor]) !== 2) {
        valid = false;
        cursor += 1;
        continue;
      }
      const job = entryAt(cursor, 2);
      if (job === null || !emptyMappingValue(job.value) || !unique(jobNames, job.key)) {
        valid = false;
        cursor += 1;
        continue;
      }
      const jobEnd = blockEnd(cursor + 1, 2, limit);
      const attributeNames = new Set();
      for (let attributeIndex = nextSignificant(cursor + 1, jobEnd); attributeIndex < jobEnd; attributeIndex = nextSignificant(attributeIndex, jobEnd)) {
        if (indent(lines[attributeIndex]) !== 4) {
          valid = false;
          attributeIndex += 1;
          continue;
        }
        const attribute = entryAt(attributeIndex, 4);
        if (attribute === null || !unique(attributeNames, attribute.key) || forbiddenValueForm(attribute.value)) {
          valid = false;
          attributeIndex += 1;
          continue;
        }
        const attributeEnd = blockEnd(attributeIndex + 1, 4, jobEnd);
        if (attribute.key === "services") {
          if (!emptyMappingValue(attribute.value)) {
            valid = false;
          } else {
            parseServices(attributeIndex + 1, attributeEnd);
          }
        }
        attributeIndex = attributeEnd;
      }
      cursor = jobEnd;
    }
  };

  for (let cursor = nextSignificant(0, lines.length); cursor < lines.length; cursor = nextSignificant(cursor, lines.length)) {
    if (indent(lines[cursor]) !== 0) {
      valid = false;
      cursor += 1;
      continue;
    }
    const root = entryAt(cursor, 0);
    if (root === null || !unique(rootKeys, root.key) || forbiddenValueForm(root.value)) {
      valid = false;
      cursor += 1;
      continue;
    }
    const rootEnd = blockEnd(cursor + 1, 0);
    if (root.key === "jobs") {
      jobsCount += 1;
      if (!emptyMappingValue(root.value)) {
        valid = false;
      } else {
        parseJobs(cursor + 1, rootEnd);
      }
    }
    cursor = rootEnd;
  }

  return valid && jobsCount === 1 ? services : null;
}

function hasClosedServiceLogging(workflow) {
  const services = privateServiceOptions(workflow);
  if (!services || services.length === 0) return false;
  return services.every(({ optionFields }) => {
    if (optionFields.length !== 1) return false;
    // Accept only this repository's simple, one-option-per-line form. Quoting,
    // interpolation or a value on a following line can hide another Docker
    // flag after YAML folding / argument parsing; reject rather than guess.
    if (!optionFields[0].every((option) => /^--[a-z][a-z0-9-]*(?:(?:=| )[A-Za-z0-9_./:@%+,-]+)?$/.test(option))) return false;
    const driverMentions = optionFields[0].filter((option) => /^--log-driver(?:=|\s|$)/.test(option));
    return driverMentions.length === 1 && /^--log-driver(?:=|\s+)none$/.test(driverMentions[0]);
  });
}

// Geschlossene Sonar-Grammatik: jede Änderung an Triggern, Matrix, Befehlen, Secrets,
// Upload-Pfaden oder Abhängigkeiten braucht ein neues geprüftes Vertrags-Digest.
// So können zusätzliche YAML-Keys, Aliase oder übersprungene Schutzschritte die
// positive Allowlist nicht durch scheinbar sichere Textfragmente umgehen.
// Diagnose-Upload ausschließlich vom Sealing-Schritt: jeder Glob-Treffer wird
// erneut verschlüsselt. Installer-Upload nur mit exakt geprüften Dateipfaden.
const SONAR_WORKFLOW_SHA256 = "01158d271439d444761eea9739c28d89758e71204cc45c76aa86bf0223ed6677";
export function validateSonarWorkflow(workflow) {
  if (typeof workflow !== "string"
      || createHash("sha256").update(workflow).digest("hex") !== SONAR_WORKFLOW_SHA256) {
    return ["sonar-build.yml: geschlossener Vertrag verletzt (dispatch-only, Deploy-Key-Pins, vertrauliche Builds, nur Installer/verschlüsselte Diagnosen, kein Überschreiben, App-Token nur sonar-releases)"];
  }
  return [];
}

// Die Upload- und Release-Logik liegt in Helfern; auch diese gehören zur Allowlist.
const SONAR_HELPER_SHA256 = {
  "encrypt-confidential-log.mjs": "30543468128ed79573db015680dbb602f0aaaecf05d860320594f2eb64388764",
  "checkout-private-source.sh": "6f5bc66f16315f3dd1a10cc6842d15070990e0139fc31abe742a44aaf0f242a0",
  "sonar-build.sh": "cffc972709c08fb4c9bc217a7c88b522949f92399a9213cdb38426d710415b9c",
  "sonar-minisign.sh": "366958a33688dbea00fe52b49be5a5429971a58cf2f8f887267509c5bb91bc73",
  "sonar-release.mjs": "2a1bc4a9ea5598b94800fcd6d303499a3cfa4e8317b28cde70955144ee691538",
};
export function validateSonarHelpers(helpers) {
  return Object.entries(SONAR_HELPER_SHA256).flatMap(([name, digest]) =>
    typeof helpers[name] === "string" && createHash("sha256").update(helpers[name]).digest("hex") === digest
      ? [] : [`sonar-build.yml: ${name} verletzt den geprüften Installer-/Signatur-/Unveränderlichkeitsvertrag`]);
}
function loadSonarHelpers() {
  return Object.fromEntries(Object.keys(SONAR_HELPER_SHA256).map(name => {
    try { return [name, readFileSync(join(ROOT, "scripts", name), "utf8")]; }
    catch { return [name, undefined]; }
  }));
}

export function validateSourceConfidentiality(workflows, assetSelector) {
  const errors = [...validateSonarWorkflow(workflows["sonar-build.yml"]), ...validateSonarHelpers(loadSonarHelpers())];
  if (workflows["native-cli-hermetic.yml"] !== NATIVE_CLI_WORKFLOW) errors.push("native-cli-hermetic.yml: exact manual pinned confidential native proof policy required");
  const require = (condition, message) => { if (!condition) errors.push(message); };

  for (const [name, workflow] of Object.entries(workflows)) {
    require(/^\s{2}workflow_dispatch:\s*$/m.test(workflow), `${name}: workflow_dispatch must be the only executable trigger`);
    require(!/^\s{2}(pull_request|push|pull_request_target|schedule):/m.test(workflow), `${name}: secret-bearing public workflow must not have an automatic or fork trigger`);
    require(workflow.includes("persist-credentials: false"), `${name}: public checkout credentials must not persist`);
    require(workflow.includes("scripts/run-confidential.sh"), `${name}: private command output must use the confidential runner`);
    require(!/uses:\s*(?:swatinem\/rust-cache|actions\/cache)@/.test(workflow), `${name}: private build outputs must not enter a public Actions cache`);

    for (const line of workflow.split("\n")) {
      const match = line.match(/^\s*(?:-\s*)?uses:\s*([^\s#]+)/);
      if (!match || match[1].startsWith("./")) continue;
      const ref = match[1].split("@").at(-1);
      require(/^[0-9a-f]{40}$/.test(ref ?? ""), `${name}: action reference must be immutable: ${match[1]}`);
    }
  }

  for (const name of PRIVATE_POSTGRES_WORKFLOWS) {
    const workflow = workflows[name] ?? "";
    require(hasClosedServiceLogging(workflow), `${name}: every private service options field must set exactly one --log-driver none`);
  }

  const isolatedU1ChatSuite = 'run: bash "$GITHUB_WORKSPACE/gate/scripts/run-confidential.sh" u1-chat-tests bun test --isolate';
  for (const name of ["u1-chat-pr-check.yml", "fleet-source-check.yml"]) {
    const commands = (workflows[name] ?? "").split("\n").map((line) => line.trim()).filter((line) => line.includes("u1-chat-tests"));
    require(
      commands.length === 1 && commands[0] === isolatedU1ChatSuite,
      `${name}: u1-chat backend suite must run exactly once with Bun per-file isolation and no test filters`,
    );
  }

  const u1Chat = workflows["u1-chat-pr-check.yml"] ?? "";
  const u1Suite = u1Chat.split("      - name: Backend- und Boundary-Suite\n");
  const suiteStep = u1Suite[1]?.split("\n      - ")[0] ?? "";
  require(
    u1Suite.length === 2
      && suiteStep.includes("id: backend_tests")
      && suiteStep.includes("SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64: ${{ inputs.diagnostic_public_key_base64 }}")
      && suiteStep.includes("SCAI_ENCRYPTED_DIAGNOSTIC_PATH: ${{ inputs.diagnostic_public_key_base64 != '' && format('{0}/u1-chat-diagnostic.json', runner.temp) || '' }}")
      && suiteStep.includes(isolatedU1ChatSuite),
    "u1-chat-pr-check.yml: private test diagnostics require the one-time-key confidential runner",
  );
  const u1Uploads = u1Chat.split("      - name: Verschluesselte u1-chat-Diagnostik sichern\n");
  const uploadStep = u1Uploads[1]?.split("\n      - ")[0] ?? "";
  const uploadLines = uploadStep.split("\n").map((line) => line.trim());
  require(
    u1Uploads.length === 2
      && uploadLines.filter((line) => line.startsWith("if:")).length === 1
      && uploadLines.includes("if: failure() && steps.backend_tests.outcome == 'failure' && inputs.diagnostic_public_key_base64 != ''")
      && uploadLines.filter((line) => line.startsWith("path:")).length === 1
      && uploadLines.includes("path: ${{ runner.temp }}/u1-chat-diagnostic.json")
      && uploadLines.includes("if-no-files-found: error")
      && uploadLines.includes("retention-days: 1"),
    "u1-chat-pr-check.yml: only the keyed failure envelope may be uploaded for one day",
  );
  for (const decoder of ["pdfinfo", "djpeg", "pngcheck", "jq"]) {
    require(u1Chat.includes(`command -v ${decoder}`), `u1-chat-pr-check.yml: required backend test executable is not checked: ${decoder}`);
  }

  const pr = workflows["pr-check.yml"] ?? "";
  requirePrContract(pr, require);
  for (const error of validatePrDiagnosticInventory(pr)) require(false, error);
  for (const label of [
    "npm-ci", "frontend-unit-tests", "cli-drift", "release-meta", "plugin-bundles", "no-demo-data",
    "frontend-build", "support-diagnostics-proof", "meet-visual-proof", "chat-dock-visual-proof", "sentinel-crm-proof", "sentinel-routing-proof", "cargo-test", "native-cargo-check",
    "revenue-proof-dependencies", "revenue-proof-esbuild", "billing-production-proof", "offers-v01-proof", "workgraph-blackbox-proof", "revenue-proof-artifacts",
    "workspace-tabs-proof", "workspace-app-plugins-proof", "subunit-call-proof", "workforce-inbox-proof",
    "native-product-binary", "native-pkce-tests", "native-keyring-smoke",
    "trace-fmt", "trace-core-check", "trace-core-clippy", "trace-core-test",
    "trace-native-check", "trace-native-clippy", "trace-native-test", "trace-native-build",
    "trace-macos-app-package", "trace-macos-setup-package",
  ]) {
    require(pr.includes(`run-confidential.sh\" ${label}`), `pr-check.yml: ${label} must suppress private output`);
  }
  require(!/git clone[^\n]*--branch/.test(pr), "pr-check.yml: a mutable branch clone cannot prove an exact source SHA");
  require(
    pr.indexOf("uses: oven-sh/setup-bun@") >= 0
      && pr.indexOf("uses: oven-sh/setup-bun@") < pr.indexOf("name: Quellcode auschecken (privates Repo, read-only Deploy-Key)"),
    "pr-check.yml: Bun setup must complete before private source checkout",
  );
  const sourceCheckoutBlocks = [...pr.matchAll(/- name: Quellcode auschecken \(privates Repo, read-only Deploy-Key\)[\s\S]*?(?=\n      - (?:name:|uses:))/g)].map((match) => match[0]);
  require(sourceCheckoutBlocks.length === 2, "pr-check.yml: both private source checkout steps must remain explicit");
  for (const block of sourceCheckoutBlocks) {
    const validation = block.indexOf('bash "$GITHUB_WORKSPACE/gate/scripts/validate-private-source-ref.sh" "$SRC_REF"');
    const keyMaterial = block.indexOf('key_file="$HOME/.ssh/scai_src"');
    require(validation >= 0 && keyMaterial > validation, "pr-check.yml: source refs must be allowlist-validated before deploy-key material is created");
    require(block.includes('git -C src fetch --depth 1 -- origin "$SRC_REF"'), "pr-check.yml: source fetch must terminate options before the validated ref");
  }
  require(!pr.includes('git -C src fetch --depth 1 origin "$SRC_REF"'), "pr-check.yml: source fetch must not accept ref-shaped options");
  require(pr.includes('git -C trace-src fetch --depth 1 -- origin "$SRC_REF"'), "pr-check.yml: Trace fetch must terminate options before its validated SHA");
  require((pr.match(/echo "::error::Checkout-Drift: erwartet \$SRC_REF/g) ?? []).length === 2, "pr-check.yml: both jobs must reject exact-SHA checkout drift");
  require(!/^\s+path:\s*src\/?\s*$/m.test(pr), "pr-check.yml: the private source tree must never be uploaded as an artifact");
  require(!/^\s+path:\s*trace-src\/?\s*$/m.test(pr), "pr-check.yml: the private Trace source tree must never be uploaded as an artifact");
  require(!/^\s+path:.*scai-revenue-source-shots/m.test(pr), "pr-check.yml: raw Revenue source proof output must never be uploaded as an artifact");
  require(!/^\s+path:.*\.cache\/u1-shots\/scai-workgraph-blackbox/m.test(pr), "pr-check.yml: raw Workgraph source proof output must never be uploaded as an artifact");
  // Öffentliches Repo: Proof-Screenshots NUR als verschlüsselter Umschlag (TJ 2026-10-07:
  // öffentlich nur Installer, nichts Erkennbares — auch keine „bereinigten“ UI-Bilder).
  // Jeder Klartext-Upload aus u1-shots, *-proof/-Ordnern oder als PNG ist verboten.
  const prSteps = pr.split(/^      - name: /m);
  require(
    !prSteps.some((step) => step.includes("uses: actions/upload-artifact@")
      && /^\s+path:.*(?:\.cache\/u1-shots|-proof\/|\.png)/m.test(step)),
    "pr-check.yml: proof screenshots must never be uploaded in plaintext (public repository)",
  );
  const sealedShots = (label, key, dir) => {
    const seal = prSteps.find((step) => step.includes(`dir="${dir}"`) && step.includes("encrypt-confidential-log.mjs")) ?? "";
    const upload = prSteps.find((step) => step.includes("uses: actions/upload-artifact@")
      && step.includes(`path: \${{ runner.temp }}/scai-${key}-encrypted-shots.json`)) ?? "";
    require(
      seal.includes("inputs.diagnostic_public_key_base64 != ''")
        && seal.includes(`"$RUNNER_TEMP/scai-${key}-encrypted-shots.json"`)
        && upload.includes(`name: scai-${key}-encrypted-shots-\${{ github.run_id }}`),
      `pr-check.yml: ${label} proof may upload only its encrypted screenshot envelope`,
    );
    return seal;
  };
  sealedShots("Chat-Dock", "chat-dock", "$HOME/.cache/u1-shots/scai-chat-dock");
  sealedShots("Sentinel CRM", "sentinel-crm", "$HOME/.cache/u1-shots/sentinel-crm-2026");
  const revenueSeal = sealedShots("Revenue", "revenue-browser", "$RUNNER_TEMP/scai-revenue-browser-proof");
  require(
    (pr.match(/run-confidential\.sh" native-keyring-smoke/g) ?? []).length === 2
      && (pr.match(/--example a1_keyring_smoke/g) ?? []).length === 2,
    "pr-check.yml: keyring smoke must stay an example in both manifest-derived branches",
  );
  require(
    pr.includes("if grep -Eq '^[[:space:]]*a1-keyring-smoke[[:space:]]*=' src-tauri/Cargo.toml; then")
      && (pr.match(/--features a1-keyring-smoke/g) ?? []).length === 1
      && !pr.includes("keyring_features"),
    "pr-check.yml: keyring smoke must support old and new pinned manifests without Bash 3.2 empty-array expansion",
  );
  require(!pr.includes("--bin a1_keyring_smoke"), "pr-check.yml: keyring smoke must not reintroduce a Cargo bin target");
  require(
    pr.includes("trace_ref muss ein unveränderlicher 40-Zeichen-SHA sein."),
    "pr-check.yml: standalone Trace checks must reject mutable refs",
  );
  require(
    pr.includes("Trace-Checkout-Drift: erwartet $SRC_REF"),
    "pr-check.yml: standalone Trace checks must verify the exact checked-out SHA",
  );
  require(
    /trace-standalone:[\s\S]*?if: inputs\.trace_ref != ''[\s\S]*?runner: ubuntu-latest[\s\S]*?runner: macos-15[\s\S]*?runner: macos-15-intel[\s\S]*?runner: windows-2025/.test(pr),
    "pr-check.yml: standalone Trace must retain Linux, macOS ARM/Intel and Windows lanes",
  );
  require(
    /if: failure\(\) && steps\.trace_native_check\.outcome == 'failure' && inputs\.diagnostic_public_key_base64 != ''[\s\S]{0,350}?path: \$\{\{ runner\.temp \}\}\/trace-native-diagnostic\/\*\.encrypted\.json/.test(pr),
    "pr-check.yml: Trace native diagnostics may upload only a one-time-key encrypted envelope",
  );
  require(
    pr.includes("trace_bundle_public_key_base64"),
    "pr-check.yml: internal Trace bundles require an explicit one-time recipient key",
  );
  require(
    /name: Verschlüsselten internen Trace-Mac-Bundle bereitstellen[\s\S]{0,500}?if: matrix\.label == 'macos-arm64' && inputs\.trace_bundle_public_key_base64 != ''[\s\S]{0,500}?path: \$\{\{ runner\.temp \}\}\/trace-host-macos-arm64-internal\.tar\.gz\.envelope\.json/.test(pr),
    "pr-check.yml: internal Trace bundle uploads must contain only the one-time-key encrypted envelope",
  );
  require(
    pr.includes('node "$GITHUB_WORKSPACE/gate/scripts/encrypt-confidential-log.mjs"')
      && pr.includes('rm -rf "$bundle_root" "$dmg" "$delivery"'),
    "pr-check.yml: plaintext Trace bundles must be encrypted and removed before upload",
  );
  require(
    pr.includes('customer_ready:false') && pr.includes('distribution_policy:"internal-signed-not-notarized"'),
    "pr-check.yml: Apple-Development Trace artifacts must remain explicitly non-customer-ready",
  );
  const tracePrepackage = pr.indexOf("name: Trace-App ohne vertrauliche Codeidentität vorpaketieren");
  const traceSigningImport = pr.indexOf("name: Interne macOS-Codeidentität für Trace importieren");
  const traceSigning = pr.indexOf("name: Signierten Trace-App-Bundle bauen und einmalig verschlüsseln");
  require(
    tracePrepackage >= 0 && tracePrepackage < traceSigningImport && traceSigningImport < traceSigning,
    "pr-check.yml: private Trace packaging must finish before signing secrets are imported",
  );
  require(
    traceSigningImport < 0 || !pr.slice(traceSigningImport).includes("bash scripts/build-macos-app.sh"),
    "pr-check.yml: no private Trace packaging script may execute after signing secrets are imported",
  );
  require(
    traceSigningImport < 0 || !pr.slice(traceSigningImport).includes("bash scripts/build-macos-setup-app.sh"),
    "pr-check.yml: no private Trace setup packaging script may execute after signing secrets are imported",
  );
  require(
    pr.includes('test ! -L "$bundle_root/Trace Host.app"')
      && pr.includes('test -z "$(find "$bundle_root/Trace Host.app" -type l -print -quit)"')
      && pr.includes('test ! -L "$bundle_root/Trace einrichten.app"')
      && pr.includes('test -z "$(find "$bundle_root/Trace einrichten.app" -type l -print -quit)"'),
    "pr-check.yml: both prepackaged Trace apps must reject symlinks before signing",
  );
  require(
    pr.includes('setup_bundle_identifier:"ai.subunit.trace-setup"')
      && pr.includes('test "$(sed -n \'s/^Identifier=//p\' <<<"$setup_signature")" = "ai.subunit.trace-setup"'),
    "pr-check.yml: the internal setup app must be identity-bound in evidence and signing checks",
  );
  require(
    !/^\s+path: .*trace-host.*\.dmg\s*$/m.test(pr),
    "pr-check.yml: plaintext Trace DMGs must never be uploaded from the public workflow",
  );
  require(
    !/^\s+path: .*trace-host.*\.tar\.gz\s*$/m.test(pr),
    "pr-check.yml: plaintext Trace delivery archives must never be uploaded from the public workflow",
  );
  require(
    /if: failure\(\) &&[^\n]*inputs\.diagnostic_public_key_base64 != ''[\s\S]{0,350}?path: \$\{\{ runner\.temp \}\}\/scai-support-diagnostic\/\*\.encrypted\.json/.test(pr),
    "pr-check.yml: Support diagnostics may upload only a one-time-key encrypted envelope",
  );
  require(
    /if: failure\(\) &&[^\n]*inputs\.diagnostic_public_key_base64 != ''[\s\S]{0,350}?path: \$\{\{ runner\.temp \}\}\/scai-pages-diagnostic\/\*\.encrypted\.json/.test(pr),
    "pr-check.yml: Pages diagnostics may upload only a one-time-key encrypted envelope",
  );
  require(
    /if: failure\(\) &&[^\n]*inputs\.diagnostic_public_key_base64 != ''[\s\S]{0,350}?path: \$\{\{ runner\.temp \}\}\/scai-chat-dock-diagnostic\/\*\.encrypted\.json/.test(pr),
    "pr-check.yml: Chat-Dock diagnostics may upload only a one-time-key encrypted envelope",
  );
  require(
    /if: failure\(\) &&[^\n]*inputs\.diagnostic_public_key_base64 != ''[\s\S]{0,350}?path: \$\{\{ runner\.temp \}\}\/scai-sentinel-crm-diagnostic\/\*\.encrypted\.json/.test(pr),
    "pr-check.yml: Sentinel CRM diagnostics may upload only a one-time-key encrypted envelope",
  );
  const routingProofSteps = pr.split("      - name: Sentinel Lead Ownership und SLA Routing beweisen\n");
  const routingProof = routingProofSteps[1]?.split("\n      - ")[0] ?? "";
  require(
    routingProofSteps.length === 2
      && routingProof.includes("id: routing_proof")
      && routingProof.includes("SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64: ${{ inputs.diagnostic_public_key_base64 }}")
      && routingProof.includes("SCAI_ENCRYPTED_DIAGNOSTIC_PATH: ${{ inputs.diagnostic_public_key_base64 != '' && format('{0}/scai-sentinel-routing-diagnostic/failure.encrypted.json', runner.temp) || '' }}")
      && routingProof.includes('run: bash "$GITHUB_WORKSPACE/gate/scripts/run-confidential.sh" sentinel-routing-proof node scripts/verify-sentinel-routing.mjs'),
    "pr-check.yml: Sentinel Routing proof must seal private failures with the supplied one-time key",
  );
  require(
    /if: failure\(\) && steps\.routing_proof\.outcome == 'failure' && inputs\.diagnostic_public_key_base64 != ''[\s\S]{0,350}?path: \$\{\{ runner\.temp \}\}\/scai-sentinel-routing-diagnostic\/\*\.encrypted\.json/.test(pr),
    "pr-check.yml: Sentinel Routing diagnostics may upload only a one-time-key encrypted envelope",
  );
  require(
    /if \[ -f scripts\/verify-sentinel-forecast\.mjs \]; then[\s\S]{0,220}?sentinel_forecast=true[\s\S]{0,220}?sentinel_forecast=false/.test(pr),
    "pr-check.yml: newer Sentinel proofs must be detected before older source refs are gated",
  );
  require(
    /if \[ -f scripts\/verify-sentinel-crm-2026\.mjs \]; then[\s\S]{0,220}?sentinel_crm=true[\s\S]{0,220}?sentinel_crm=false/.test(pr),
    "pr-check.yml: Sentinel CRM proof must be detected before older source refs are gated",
  );
  require(
    /if \[ -f scripts\/verify-workgraph-blackbox\.mjs \]; then[\s\S]{0,220}?workgraph_blackbox=true[\s\S]{0,220}?workgraph_blackbox=false/.test(pr),
    "pr-check.yml: Workgraph proof must be optional for older source refs",
  );
  require(
    /if \[ -f scripts\/verify-moco-parity\.mjs \]; then[\s\S]{0,220}?moco_parity=true[\s\S]{0,220}?moco_parity=false/.test(pr),
    "pr-check.yml: MOCO parity proof must be optional for older source refs",
  );
  require(
    /if \[ -f scripts\/verify-workforce-inbox\.mjs \]; then[\s\S]{0,220}?workforce_inbox=true[\s\S]{0,220}?workforce_inbox=false/.test(pr),
    "pr-check.yml: Workforce Inbox proof must be optional for older source refs",
  );
  for (const contract of [
    "subunit_call_host=false",
    "subunit_call_proof=false",
    "[ ! -f src/call/CallSessionHost.tsx ] || subunit_call_host=true",
    "[ ! -f scripts/verify-subunit-call.mjs ] || subunit_call_proof=true",
    "echo \"subunit_call=true\" >> \"$GITHUB_OUTPUT\"",
    "echo \"subunit_call=false\" >> \"$GITHUB_OUTPUT\"",
  ]) {
    require(pr.includes(contract), `pr-check.yml: Subunit Call proof detection must retain: ${contract}`);
  }
  require(
    /if \[ "\$subunit_call_host" = true \] && \[ "\$subunit_call_proof" = true \]; then[\s\S]{0,180}?elif \[ "\$subunit_call_host" = false \] && \[ "\$subunit_call_proof" = false \]; then[\s\S]{0,300}?else[\s\S]{0,240}?exit 1/.test(pr),
    "pr-check.yml: partial Subunit Call capability availability must fail closed",
  );
  for (const contract of [
    "workspace_tabs=false",
    "workspace_app_plugins=false",
    "[ ! -f scripts/verify-workspace-tabs.mjs ] || workspace_tabs=true",
    "[ ! -f scripts/verify-workspace-app-plugins.mjs ] || workspace_app_plugins=true",
    "echo \"workspace_browser=true\" >> \"$GITHUB_OUTPUT\"",
    "echo \"workspace_browser=false\" >> \"$GITHUB_OUTPUT\"",
  ]) {
    require(pr.includes(contract), `pr-check.yml: Workspace proof detection must retain: ${contract}`);
  }
  require(
    /if \[ "\$workspace_tabs" = true \] && \[ "\$workspace_app_plugins" = true \]; then[\s\S]{0,180}?elif \[ "\$workspace_tabs" = false \] && \[ "\$workspace_app_plugins" = false \]; then[\s\S]{0,300}?else[\s\S]{0,240}?exit 1/.test(pr),
    "pr-check.yml: partial Workspace harness availability must fail closed",
  );
  require(
    /name: Sentinel CRM 2026 visuell und interaktiv beweisen[\s\S]{0,180}?if: steps\.source_proofs\.outputs\.sentinel_crm == 'true'/.test(pr),
    "pr-check.yml: Sentinel CRM proof must stay strict when its source harness exists",
  );
  require(
    /name: Sentinel Forecast Command Desk beweisen[\s\S]{0,180}?if: steps\.source_proofs\.outputs\.sentinel_forecast == 'true'/.test(pr),
    "pr-check.yml: Sentinel forecast proof must stay strict when its source harness exists",
  );
  for (const contract of [
    "billing_revenue=false",
    "offers_revenue=false",
    "[ ! -f scripts/verify-billing-production.mjs ] || billing_revenue=true",
    "[ ! -f scripts/verify-offers-v01.mjs ] || offers_revenue=true",
    "echo \"revenue_browser=true\" >> \"$GITHUB_OUTPUT\"",
    "echo \"revenue_browser=false\" >> \"$GITHUB_OUTPUT\"",
  ]) {
    require(pr.includes(contract), `pr-check.yml: Revenue proof detection must retain: ${contract}`);
  }
  require(
    /if \[ "\$billing_revenue" = true \] && \[ "\$offers_revenue" = true \]; then[\s\S]{0,180}?elif \[ "\$billing_revenue" = false \] && \[ "\$offers_revenue" = false \]; then[\s\S]{0,260}?else[\s\S]{0,220}?exit 1/.test(pr),
    "pr-check.yml: partial Revenue harness availability must fail closed",
  );
  require(
    /name: Revenue-Browser-Abhängigkeiten prüfen[\s\S]{0,500}?if: steps\.source_proofs\.outputs\.revenue_browser == 'true' \|\| steps\.source_proofs\.outputs\.workgraph_blackbox == 'true'[\s\S]{0,500}?run-confidential\.sh" revenue-proof-dependencies npx --no-install playwright --version[\s\S]{0,180}?run-confidential\.sh" revenue-proof-esbuild npx --no-install esbuild --version/.test(pr),
    "pr-check.yml: Revenue browser dependencies must be installed and resolved without an implicit npx download",
  );
  require(
    /name: Billing produktionsnah visuell und interaktiv beweisen[\s\S]{0,700}?if: always\(\) && steps\.source_proofs\.outputs\.revenue_browser == 'true' && steps\.revenue_proof_dependencies\.outcome == 'success'[\s\S]{0,700}?SCAI_BILLING_PROOF_DIR: \$\{\{ runner\.temp \}\}\/scai-revenue-source-shots\/billing[\s\S]{0,700}?run-confidential\.sh" billing-production-proof node scripts\/verify-billing-production\.mjs/.test(pr),
    "pr-check.yml: Billing Revenue proof must run confidentially into its isolated fixture directory",
  );
  require(
    /name: Angebote v0\.1 visuell und interaktiv beweisen[\s\S]{0,700}?if: always\(\) && steps\.source_proofs\.outputs\.revenue_browser == 'true' && steps\.revenue_proof_dependencies\.outcome == 'success'[\s\S]{0,700}?SCAI_OFFERS_PROOF_DIR: \$\{\{ runner\.temp \}\}\/scai-revenue-source-shots\/offers[\s\S]{0,700}?run-confidential\.sh" offers-v01-proof node scripts\/verify-offers-v01\.mjs/.test(pr),
    "pr-check.yml: Offers Revenue proof must run confidentially into its isolated fixture directory",
  );
  require(
    /name: Workgraph Blackbox visuell und interaktiv beweisen[\s\S]{0,750}?if: always\(\) && steps\.source_proofs\.outputs\.workgraph_blackbox == 'true' && steps\.revenue_proof_dependencies\.outcome == 'success'[\s\S]{0,750}?run-confidential\.sh" workgraph-blackbox-proof node scripts\/verify-workgraph-blackbox\.mjs/.test(pr),
    "pr-check.yml: Workgraph proof must run confidentially whenever its source harness exists",
  );
  require(
    /name: MOCO-Paritaetsprotokoll visuell und interaktiv beweisen[\s\S]{0,500}?if: steps\.source_proofs\.outputs\.moco_parity == 'true'[\s\S]{0,500}?MOCO_PARITY_PROOF_OUT: \$\{\{ runner\.temp \}\}\/scai-moco-parity-proof[\s\S]{0,500}?run-confidential\.sh" moco-parity-proof node scripts\/verify-moco-parity\.mjs/.test(pr),
    "pr-check.yml: MOCO parity browser proof must run confidentially when its source harness exists",
  );
  require(
    /name: Persönliche Workforce-Inbox und Übergaben visuell beweisen[\s\S]{0,700}?if: always\(\) && steps\.source_proofs\.outputs\.workforce_inbox == 'true'[\s\S]{0,700}?SCAI_WORKFORCE_INBOX_PROOF_DIR: \$\{\{ runner\.temp \}\}\/scai-workforce-inbox-proof[\s\S]{0,700}?run-confidential\.sh" workforce-inbox-proof node scripts\/verify-workforce-inbox\.mjs/.test(pr),
    "pr-check.yml: Workforce Inbox proof must run confidentially into its isolated fixture directory",
  );
  require(
    /name: Arbeitsbereich mit Tabs und geteilten Flächen im Web beweisen[\s\S]{0,700}?if: steps\.source_proofs\.outputs\.workspace_browser == 'true'[\s\S]{0,700}?SCAI_WORKSPACE_PROOF_OUT: \$\{\{ runner\.temp \}\}\/scai-workspace-tabs[\s\S]{0,700}?SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64: \$\{\{ inputs\.diagnostic_public_key_base64 \}\}[\s\S]{0,700}?SCAI_ENCRYPTED_DIAGNOSTIC_PATH: \$\{\{ inputs\.diagnostic_public_key_base64 != '' && format\('\{0\}\/scai-workspace-tabs-diagnostic\/failure\.encrypted\.json', runner\.temp\) \|\| '' \}\}[\s\S]{0,700}?run-confidential\.sh" workspace-tabs-proof node scripts\/verify-workspace-tabs\.mjs/.test(pr),
    "pr-check.yml: Workspace tab proof must run confidentially when both source harnesses exist",
  );
  require(
    /name: Arbeitsbereich mit App-Modus-Plugins beweisen[\s\S]{0,700}?if: steps\.source_proofs\.outputs\.workspace_browser == 'true'[\s\S]{0,700}?SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64: \$\{\{ inputs\.diagnostic_public_key_base64 \}\}[\s\S]{0,700}?SCAI_ENCRYPTED_DIAGNOSTIC_PATH: \$\{\{ inputs\.diagnostic_public_key_base64 != '' && format\('\{0\}\/scai-workspace-app-plugins-diagnostic\/failure\.encrypted\.json', runner\.temp\) \|\| '' \}\}[\s\S]{0,700}?run-confidential\.sh" workspace-app-plugins-proof node scripts\/verify-workspace-app-plugins\.mjs/.test(pr),
    "pr-check.yml: Workspace app-plugin proof must run confidentially when both source harnesses exist",
  );
  require(
    /name: Verschlüsselte Arbeitsbereich-Tabs-Fehlerdiagnostik bereitstellen[\s\S]{0,500}?if: failure\(\) && steps\.workspace_tabs_proof\.outcome == 'failure' && inputs\.diagnostic_public_key_base64 != ''[\s\S]{0,500}?path: \$\{\{ runner\.temp \}\}\/scai-workspace-tabs-diagnostic\/\*\.encrypted\.json[\s\S]{0,200}?retention-days: 1/.test(pr),
    "pr-check.yml: Workspace tab diagnostics may upload only a one-time-key encrypted envelope",
  );
  require(
    /name: Verschlüsselte Arbeitsbereich-App-Plugins-Fehlerdiagnostik bereitstellen[\s\S]{0,500}?if: failure\(\) && steps\.workspace_app_plugins_proof\.outcome == 'failure' && inputs\.diagnostic_public_key_base64 != ''[\s\S]{0,500}?path: \$\{\{ runner\.temp \}\}\/scai-workspace-app-plugins-diagnostic\/\*\.encrypted\.json[\s\S]{0,200}?retention-days: 1/.test(pr),
    "pr-check.yml: Workspace app-plugin diagnostics may upload only a one-time-key encrypted envelope",
  );
  require(
    /name: Subunit Call im Browser einschließlich Aufnahme und Native-Quit-Schutz beweisen[\s\S]{0,700}?if: always\(\) && steps\.source_proofs\.outputs\.subunit_call == 'true'[\s\S]{0,700}?SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64: \$\{\{ inputs\.diagnostic_public_key_base64 \}\}[\s\S]{0,700}?SCAI_ENCRYPTED_DIAGNOSTIC_PATH: \$\{\{ inputs\.diagnostic_public_key_base64 != '' && format\('\{0\}\/scai-subunit-call-diagnostic\/failure\.encrypted\.json', runner\.temp\) \|\| '' \}\}[\s\S]{0,700}?run-confidential\.sh" subunit-call-proof node scripts\/verify-subunit-call\.mjs/.test(pr),
    "pr-check.yml: Subunit Call proof must run confidentially whenever its source harness exists",
  );
  require(
    /name: Verschlüsselte Subunit-Call-Fehlerdiagnostik bereitstellen[\s\S]{0,500}?if: failure\(\) && steps\.subunit_call_proof\.outcome == 'failure' && inputs\.diagnostic_public_key_base64 != ''[\s\S]{0,500}?path: \$\{\{ runner\.temp \}\}\/scai-subunit-call-diagnostic\/\*\.encrypted\.json[\s\S]{0,200}?retention-days: 1/.test(pr),
    "pr-check.yml: Subunit Call diagnostics may upload only a one-time-key encrypted envelope",
  );
  require(
    /name: Arbeitsbereich-Proof-Screenshots geschlossen prüfen[\s\S]{0,900}?desktop-dark-split\.png[\s\S]{0,300}?mobile-light-areas\.png[\s\S]{0,300}?mobile-dark\.png[\s\S]{0,300}?dashboard-two-instances\.png[\s\S]{0,300}?takoru-two-instances\.png[\s\S]{0,200}?halo-two-instances\.png[\s\S]{0,300}?native-menu-bridge\.png/.test(pr),
    "pr-check.yml: Workspace proof must verify the representative Web and App-mode screenshots",
  );
  const workspaceAndCallUploadPaths = [...pr.matchAll(/^\s+path:\s*(.*(?:scai-workspace-(?:tabs|app-plugins)|scai-subunit-call).*?)\s*$/gm)]
    .map((match) => match[1]);
  require(
    workspaceAndCallUploadPaths.length === 3
      && workspaceAndCallUploadPaths.includes("${{ runner.temp }}/scai-workspace-tabs-diagnostic/*.encrypted.json")
      && workspaceAndCallUploadPaths.includes("${{ runner.temp }}/scai-workspace-app-plugins-diagnostic/*.encrypted.json")
      && workspaceAndCallUploadPaths.includes("${{ runner.temp }}/scai-subunit-call-diagnostic/*.encrypted.json"),
    "pr-check.yml: raw Workspace proof output must not be uploaded; raw Call output must not be uploaded; only the three encrypted diagnostic envelopes are allowed",
  );
  require(
    !/^\s+path:\s*["']?(?:[^"'\r\n]*\.cache\/u1-shots\/subunit-call(?:\/[^"'\r\n]*)?|[^"'\r\n]*subunit-call-report\.json|[^"'\r\n]*call-[^/"'\s]*\.(?:webm|png))["']?\s*$/m.test(pr),
    "pr-check.yml: raw Subunit Call screenshots, recordings, reports, and the real proof output directory must never be uploaded",
  );
  const browserArtifactStep = pr.match(/- name: Revenue-Fixture-Screenshots geschlossen prüfen[\s\S]*?(?=\n      - name:)/)?.[0] ?? "";
  require(
    browserArtifactStep.includes("steps.source_proofs.outputs.revenue_browser == 'true' && steps.billing_revenue_proof.outcome == 'success' && steps.offers_revenue_proof.outcome == 'success'")
      && browserArtifactStep.includes("steps.source_proofs.outputs.workgraph_blackbox != 'true' || steps.workgraph_blackbox_proof.outcome == 'success'")
      && browserArtifactStep.includes("steps.source_proofs.outputs.revenue_browser != 'true' && steps.source_proofs.outputs.workgraph_blackbox == 'true' && steps.workgraph_blackbox_proof.outcome == 'success'"),
    "pr-check.yml: Revenue and Workgraph artifact modes must require their successful source proofs",
  );
  require(
    browserArtifactStep.includes("REVENUE_ARTIFACT_DIR: ${{ runner.temp }}/scai-revenue-browser-proof")
      && (browserArtifactStep.match(/run-confidential\.sh" revenue-proof-artifacts/g) ?? []).length === 3
      && browserArtifactStep.includes('"$BILLING_PROOF_DIR" "$OFFERS_PROOF_DIR" "$REVENUE_ARTIFACT_DIR" "$HOME/.cache/u1-shots/scai-workgraph-blackbox"')
      && browserArtifactStep.includes('"$BILLING_PROOF_DIR" "$OFFERS_PROOF_DIR" "$REVENUE_ARTIFACT_DIR"')
      && browserArtifactStep.includes('--workgraph-only "$HOME/.cache/u1-shots/scai-workgraph-blackbox" "$REVENUE_ARTIFACT_DIR"'),
    "pr-check.yml: Revenue and Workgraph screenshots must pass the public closed artifact sanitizer",
  );
  require(
    revenueSeal.includes("if: always() && steps.revenue_artifacts.outcome == 'success'"),
    "pr-check.yml: Revenue proof may upload only its sanitized fixture screenshot directory",
  );
  require(
    /if: failure\(\) && steps\.billing_revenue_proof\.outcome == 'failure' && inputs\.diagnostic_public_key_base64 != ''[\s\S]{0,350}?path: \$\{\{ runner\.temp \}\}\/scai-revenue-billing-diagnostic\/\*\.encrypted\.json/.test(pr),
    "pr-check.yml: Billing Revenue diagnostics may upload only a one-time-key encrypted envelope",
  );
  require(
    /if: failure\(\) && steps\.offers_revenue_proof\.outcome == 'failure' && inputs\.diagnostic_public_key_base64 != ''[\s\S]{0,350}?path: \$\{\{ runner\.temp \}\}\/scai-revenue-offers-diagnostic\/\*\.encrypted\.json/.test(pr),
    "pr-check.yml: Offers Revenue diagnostics may upload only a one-time-key encrypted envelope",
  );
  require(
    /if: failure\(\) && steps\.workgraph_blackbox_proof\.outcome == 'failure' && inputs\.diagnostic_public_key_base64 != ''[\s\S]{0,350}?path: \$\{\{ runner\.temp \}\}\/scai-workgraph-blackbox-diagnostic\/\*\.encrypted\.json/.test(pr),
    "pr-check.yml: Workgraph diagnostics may upload only a one-time-key encrypted envelope",
  );

  const auth = workflows["auth-pr-check.yml"] ?? "";
  require(/^\s+image: postgres@sha256:[0-9a-f]{64}(?:\s+#.*)?$/m.test(auth), "auth-pr-check.yml: PostgreSQL fixture image must use an immutable digest");
  for (const label of ["auth-install", "auth-db-fixture", "auth-tests", "auth-build", "auth-deploy-gate"]) {
    require(auth.includes(`run-confidential.sh" ${label}`), `auth-pr-check.yml: ${label} must suppress private output`);
  }
  require(pr.includes('bash "$GITHUB_WORKSPACE/gate/scripts/detect-recovered-source-proofs.sh" . >> "$GITHUB_OUTPUT"'), "pr-check.yml: recovered feature/proof pairs must fail closed before selection");
  // Closed step grammar: safe strings in comments/other steps cannot authorize
  // a skipped, failure-tolerant or plaintext proof or diagnostic upload.
  const recoveredSteps = pr.split(/(?=^      - )/m).slice(1).map(block => block.trimEnd());
  for (const [key, label, harness] of [["email_full_peek", "email-full-peek", "verify-email-full-peek.mjs"], ["backoffice_capacity", "backoffice-capacity", "verify-backoffice-capacity-list.mjs"], ["agents_os", "agents-os", null], ["workforce_coordination", "workforce-coordination", null], ["migration_host", "migration-host", null], ["radar", "radar", null], ["native_usage_core", "native-usage-core", null]]) {
    const expectedProof = `      - name: Restored ${label} contract beweisen
        id: ${key}_proof
        if: always() && steps.source_proofs.outputs.${key} == 'true'
        working-directory: src
        shell: bash
        env:${label === "radar" ? "\n          SOURCE_SHA: ${{ needs.preflight.outputs.source_sha }}\n          REQUEST_ID: ${{ needs.preflight.outputs.request_id }}" : ""}
          SCAI_TOOLCHAIN: \${{ github.workspace }}/src
          SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64: \${{ inputs.diagnostic_public_key_base64 }}
          SCAI_ENCRYPTED_DIAGNOSTIC_PATH: \${{ inputs.diagnostic_public_key_base64 != '' && format('{0}/scai-${label}-diagnostic/failure.encrypted.json', runner.temp) || '' }}
        run: bash "$GITHUB_WORKSPACE/gate/scripts/run-confidential.sh" ${label}-proof ${harness === null ? `bash "$GITHUB_WORKSPACE/gate/scripts/run-${label}-proof.sh"` : `node scripts/${harness}`}`;
    const expectedUpload = `      - name: Verschluesselte ${label} Fehlerdiagnostik bereitstellen
        if: failure() && steps.${key}_proof.outcome == 'failure' && inputs.diagnostic_public_key_base64 != ''
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4, immutable
        with:
          name: scai-${label}-encrypted-diagnostic-\${{ github.run_id }}
          path: \${{ runner.temp }}/scai-${label}-diagnostic/*.encrypted.json
          if-no-files-found: error
          retention-days: 1`;
    const proofs = recoveredSteps.filter(block => block.includes(`${key}_proof`) && /^      - name: Restored /m.test(block));
    const uploads = recoveredSteps.filter(block => block.startsWith(`      - name: Verschluesselte ${label} Fehlerdiagnostik bereitstellen`));
    require(proofs.length === 1 && proofs[0] === expectedProof
      && recoveredSteps.filter(block => new RegExp(`^        id: ${key}_proof$`, "m").test(block)).length === 1,
    `pr-check.yml: ${label} must run selected source proof confidentially with exact fail-closed policy`);
    require(uploads.length === 1 && uploads[0] === expectedUpload,
      `pr-check.yml: ${label} diagnostic requires the exact failed step and encrypted envelope`);
    if (["agents-os", "workforce-coordination", "migration-host", "radar"].includes(label)) {
      const expectedVisual = `      - name: Verschluesselte ${label} Visualbelege bereitstellen
        if: always() && steps.source_proofs.outputs.${key} == 'true' && (steps.${key}_proof.outcome == 'success' || steps.${key}_proof.outcome == 'failure') && steps.${key}_proof.outputs.encrypted_visual_receipt == 'true' && inputs.diagnostic_public_key_base64 != ''
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4, immutable
        with:
          name: scai-${label}-encrypted-proof-\${{ github.run_id }}
          path: \${{ runner.temp }}/scai-${label}-encrypted-proof.json
          if-no-files-found: error
          retention-days: 1`;
      const visuals = recoveredSteps.filter(block => block.startsWith(`      - name: Verschluesselte ${label} Visualbelege bereitstellen`) || block.includes(`scai-${label}-encrypted-proof`));
      require(visuals.length === 1 && visuals[0] === expectedVisual,
        `pr-check.yml: ${label} visual proof requires exact selected executed step and encrypted envelope`);
    }
  }
  require(auth.includes('scripts/checkout-private-source.sh subunit-auth') && auth.includes('"$SOURCE_SHA"'), "auth-pr-check.yml: private checkout must retain its exact source pin");
  require(auth.includes('scripts/ci/run-proof-suite.sh'), "auth-pr-check.yml: all source proof files must use the private isolated suite runner");
  require(auth.includes("SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64") && auth.includes("SCAI_ENCRYPTED_DIAGNOSTIC_PATH"), "auth-pr-check.yml: private failures require optional one-time-key encryption");
  require(auth.includes('run-confidential.sh" auth-tests bash scripts/ci/run-proof-suite.sh'), "auth-pr-check.yml: partial test commands cannot replace the full private runner");
  require(auth.includes('scripts/setup-auth-ci-databases.sh'), "auth-pr-check.yml: isolated database setup is required");
  require(auth.includes("if: failure() && inputs.diagnostic_public_key_base64 != ''"), "auth-pr-check.yml: diagnostic upload requires failure and an explicit public key");
  const authCleanup = auth.slice(auth.indexOf("      - name: Ephemere JWT-Testschluessel entfernen"));
  require(authCleanup.includes("if: always()") && ["jwt-private.pem", "jwt-public.pem", "auth-cutover-discovery-private.pem", "auth-cutover-discovery-public.pem"].every(file => authCleanup.includes(file)), "auth-pr-check.yml: both generated key families require unconditional cleanup");
  const authArtifacts = [...auth.matchAll(/uses:\s*actions\/upload-artifact@[0-9a-f]{40}[^]*?(?=\n      - name:|$)/g)];
  require(authArtifacts.length === 1 && /^\s+path: \$\{\{ runner.temp \}\}\/auth-diagnostic\.json$/m.test(authArtifacts[0]?.[0] ?? ""), "auth-pr-check.yml: artifacts must contain only the encrypted diagnostic envelope");

  const atlas = workflows["atlas-pr-check.yml"] ?? "";
  const atlasTestSteps = atlas.split("\n      - name:").filter(step=>step.includes("id: api_tests"));
  require(atlasTestSteps.length === 1 && atlasTestSteps[0].includes("SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64: ${{ inputs.diagnostic_public_key_base64 }}") && atlasTestSteps[0].includes("SCAI_ENCRYPTED_DIAGNOSTIC_PATH: ${{ inputs.diagnostic_public_key_base64 != '' && format('{0}/atlas-api-diagnostic.json', runner.temp) || '' }}"), "atlas-pr-check.yml: recipient and encrypted path must be bound to the exact test step");
  const atlasArtifacts = [...atlas.matchAll(/uses:\s*actions\/upload-artifact@[0-9a-f]{40}[^]*?(?=\n      - name:|$)/g)];
  require(atlas.includes("SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64: ${{ inputs.diagnostic_public_key_base64 }}") && atlas.includes("format('{0}/atlas-api-diagnostic.json', runner.temp)"), "atlas-pr-check.yml: diagnostics must use the optional one-time public-key envelope");
  require(atlas.includes("if: failure() && steps.api_tests.outcome == 'failure' && inputs.diagnostic_public_key_base64 != ''"), "atlas-pr-check.yml: encrypted upload requires the exact failed test step and supplied recipient");
  require(atlasArtifacts.length === 1 && /^\s+path: \$\{\{ runner.temp \}\}\/atlas-api-diagnostic\.json$/m.test(atlasArtifacts[0]?.[0] ?? ""), "atlas-pr-check.yml: only the encrypted diagnostic envelope may be uploaded");
  require(/^\s+if-no-files-found: error$/m.test(atlasArtifacts[0]?.[0] ?? "") && /^\s+retention-days: 1$/m.test(atlasArtifacts[0]?.[0] ?? ""), "atlas-pr-check.yml: diagnostic must fail closed on missing envelope and expire after one day");
  const atlasSuiteCommands = atlas.split("\n").map(line=>line.trim()).filter(line=>line.includes("run-confidential.sh") && line.includes("atlas-api-tests"));
  require(atlasSuiteCommands.length === 1 && atlasSuiteCommands[0] === 'bash "$GITHUB_WORKSPACE/gate/scripts/run-confidential.sh" atlas-api-tests bun test --isolate', "atlas-pr-check.yml: full isolated suite must remain confidential and unfiltered");

  const release = workflows["build-all.yml"] ?? "";
  require(!/uses:\s*tauri-apps\/tauri-action@/.test(release), "build-all.yml: tauri-action may expose private compiler output");
  require(release.includes('run-confidential.sh\" release-npm-ci'), "build-all.yml: npm install output must be suppressed");
  require(release.includes('run-confidential.sh\" \"tauri-build-$TARGET\"'), "build-all.yml: Tauri compiler output must be suppressed");
  require(release.includes('run-confidential.sh\" \"product-binary-$TARGET\"'), "build-all.yml: Cargo product-binary metadata must be checked confidentially before packaging");
  require(release.includes("scripts/verify-product-binary.mjs"), "build-all.yml: release packaging must reject ambiguous Cargo binary targets");
  require(release.includes('run-indexed-confidential.sh\"'), "build-all.yml: indexed private diagnostics must use the dedicated confidential runner");
  require(release.includes("scripts/validate-release-assets.sh"), "build-all.yml: release assets must pass the standalone allowlist validator");
  require(release.includes('upload-draft-assets.sh" "${ASSETS[@]}"'), "build-all.yml: only the validated asset array may be uploaded");
  require((release.match(/name: Private Trace-Credentials entfernen/g) ?? []).length >= 2, "build-all.yml: private Trace credentials must be cleaned in build and evidence jobs");
  require(/^\s+\*\.dmg\|\*\.app\.tar\.gz\|\*\.app\.tar\.gz\.sig\|\*-setup\.exe\|\*-setup\.exe\.sig\|\*\.AppImage\|\*\.AppImage\.sig\|\*\.deb\|\*\.deb\.sig\)\s*$/m.test(assetSelector), "validate-release-assets.sh: release uploads need a closed filename allowlist");
  require(assetSelector.includes('test ! -L "$candidate"'), "validate-release-assets.sh: symlinked artifacts must be rejected");

  const smoke = workflows["windows-arm-smoke.yml"] ?? "";
  for (const label of ["arm64-npm-ci", "arm64-frontend-build", "arm64-cargo-check", "arm64-preview-build"]) {
    require(smoke.includes(`run-confidential.sh\" ${label}`), `windows-arm-smoke.yml: ${label} must suppress private output`);
  }
  require(!/^\s+path:\s*src\/?\s*$/m.test(smoke), "windows-arm-smoke.yml: the private source tree must never be uploaded as an artifact");
  require(/if: failure\(\) && inputs\.diagnostic_public_key_base64 != ''[\s\S]{0,300}?path: \$\{\{ runner\.temp \}\}\/scai-arm64-diagnostic\.json/.test(smoke), "windows-arm-smoke.yml: diagnostics may upload only a one-time-key encrypted envelope");
  require(/CXXFLAGS_aarch64_pc_windows_msvc=\/EHsc[\s\S]{0,220}?MSYS2_ENV_CONV_EXCL=CXXFLAGS_aarch64_pc_windows_msvc/.test(smoke), "windows-arm-smoke.yml: MSYS path conversion must not rewrite the clang-cl exception flag");
  require(/OPENSSL_TRIPLET: arm64-windows-static-md[\s\S]{0,240}?OPENSSL_DIR=\$env:VCPKG_INSTALLATION_ROOT\\installed\\\$env:OPENSSL_TRIPLET/.test(smoke), "windows-arm-smoke.yml: SQLCipher must get the same vcpkg OpenSSL environment the release lane provisions");
  require(release.includes("openssl_triplet: arm64-windows-static-md"), "build-all.yml: the ARM64 release lane must keep the vcpkg OpenSSL triplet the smoke mirrors");

  return errors;
}

function loadWorkflows() {
  return Object.fromEntries(
    ["sonar-build.yml", "pr-check.yml", "build-all.yml", "windows-arm-smoke.yml", "u1-chat-pr-check.yml", "native-cli-hermetic.yml", ...PRIVATE_POSTGRES_WORKFLOWS].map((name) => [
      name,
      readFileSync(join(ROOT, ".github/workflows", name), "utf8"),
    ]),
  );
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  let request;
  try {
    if (process.argv[2] === "--pr-request" && process.argv.length === 3) {
      request = validatePrRequest(process.env.SOURCE_SHA, process.env.REQUEST_ID, process.env.TRACE_SHA, process.env.TRACE_BUNDLE_KEY);
      if (!process.env.GITHUB_OUTPUT) throw new Error("Preflight requires GITHUB_OUTPUT");
    } else if (process.argv.length !== 2) throw new Error("Unknown confidentiality validator mode");
  } catch (error) {
    console.error(`FAIL ${error.message}`);
    process.exit(1);
  }
  const errors = validateSourceConfidentiality(
    loadWorkflows(),
    readFileSync(join(ROOT, "scripts/validate-release-assets.sh"), "utf8"),
  );
  if (errors.length) {
    for (const error of errors) console.error(`FAIL ${error}`);
    process.exit(1);
  }
  if (request) {
    appendFileSync(process.env.GITHUB_OUTPUT, Object.entries(request).map(([key, value]) => `${key}=${value}\n`).join(""));
    console.log(`PASS source-request (source-sha=${request.source_sha}, request-id=${request.request_id})`);
  }
  console.log("PASS public source workflows :: dispatch-only, immutable actions, confidential logs, no private build cache, allowlisted artifacts");
}
