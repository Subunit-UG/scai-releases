import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { validatePrRequest, validateSourceConfidentiality, validateSonarHelpers } from "./verify-source-confidentiality.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const fixtures = Object.fromEntries(
  ["sonar-build.yml", "pr-check.yml", "build-all.yml", "windows-arm-smoke.yml", "u1-chat-pr-check.yml", "auth-pr-check.yml", "atlas-pr-check.yml", "fleet-source-check.yml", "native-cli-hermetic.yml"].map((name) => [
    name,
    readFileSync(join(ROOT, ".github/workflows", name), "utf8"),
  ]),
);
const assetSelector = readFileSync(join(ROOT, "scripts/validate-release-assets.sh"), "utf8");

test("current public source workflows fail closed on source confidentiality", () => {
  assert.deepEqual(validateSourceConfidentiality(fixtures, assetSelector), []);
});

function meetStep(name) {
  const steps = fixtures["pr-check.yml"].split(/^      - name: /m);
  const matches = steps.filter(step => step.startsWith(`${name}\n`));
  assert.equal(matches.length, 1, `exactly one ${name} step`);
  return matches[0];
}

test("Meet proof stays mandatory and pairs optional encryption with its own envelope", () => {
  const proof = meetStep("Meet-Plugin visuell und interaktiv beweisen");
  assert.match(proof, /^        id: meet_visual_proof$/m);
  assert.match(proof, /^        working-directory: src$/m);
  assert.match(proof, /^          PROOF_RUN_ID: ci$/m);
  assert.match(proof, /^          SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64: \$\{\{ inputs\.diagnostic_public_key_base64 \}\}$/m);
  assert.ok(proof.includes("SCAI_ENCRYPTED_DIAGNOSTIC_PATH: ${{ inputs.diagnostic_public_key_base64 != '' && format('{0}/scai-meet-diagnostic.json', runner.temp) || '' }}"));
  assert.match(proof, /^        run: bash "\$GITHUB_WORKSPACE\/gate\/scripts\/run-confidential\.sh" meet-visual-proof node scripts\/verify-meet-plugin\.mjs$/m);
  assert.doesNotMatch(proof, /^        (?:if|continue-on-error|timeout-minutes):/m);
  assert.equal(fixtures["pr-check.yml"].match(/^        id: meet_visual_proof$/gm)?.length, 1);
});

test("Meet encrypted upload requires its own failure and recipient with one-day retention", () => {
  const upload = meetStep("Verschlüsselte Meet-Fehlerdiagnostik bereitstellen");
  assert.match(upload, /^        if: failure\(\) && steps\.meet_visual_proof\.outcome == 'failure' && inputs\.diagnostic_public_key_base64 != ''$/m);
  assert.match(upload, /^        uses: actions\/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4, immutable$/m);
  assert.match(upload, /^          name: scai-meet-encrypted-diagnostic-\$\{\{ github\.run_id \}\}$/m);
  assert.match(upload, /^          path: \$\{\{ runner\.temp \}\}\/scai-meet-diagnostic\.json$/m);
  assert.match(upload, /^          if-no-files-found: error$/m);
  assert.match(upload, /^          retention-days: 1$/m);
  assert.doesNotMatch(upload, /^        continue-on-error:/m);
});

test("public Meet uploads are encrypted envelopes only (screenshots + failure diagnostics)", () => {
  const seal = meetStep("Meet-Proof-Screenshots verschlüsseln (öffentliches Repo, nie Klartext)");
  assert.match(seal, /^        if: always\(\) && \(steps\.meet_visual_proof\.outcome == 'success' \|\| steps\.meet_visual_proof\.outcome == 'failure'\) && inputs\.diagnostic_public_key_base64 != ''$/m);
  assert.ok(seal.includes('dir="$HOME/.cache/u1-shots/scai-meet-plugin/ci"'));
  assert.ok(seal.includes("encrypt-confidential-log.mjs"));
  const screenshots = meetStep("Meet-Proof-Screenshots (verschlüsselt) sichern");
  assert.match(screenshots, /^        if: always\(\) && steps\.meet_seal\.outcome == 'success' && steps\.meet_seal\.outputs\.sealed == 'true'$/m);
  assert.match(screenshots, /^          path: \$\{\{ runner\.temp \}\}\/scai-meet-encrypted-shots\.json$/m);
  assert.equal(screenshots.match(/^          path:/gm)?.length, 1);
  const uploads = fixtures["pr-check.yml"].split(/^      - name: /m)
    .filter(step => step.includes("uses: actions/upload-artifact@") && /scai-meet/.test(step));
  assert.equal(uploads.length, 2, "only the encrypted screenshot and failure envelopes");
});

test("plaintext proof screenshots are rejected in the public repository", () => {
  for (const [before, after] of [
    ["path: ${{ runner.temp }}/scai-pages-encrypted-shots.json", "path: ~/.cache/u1-shots/scai-pages/"],
    ["path: ${{ runner.temp }}/scai-meet-encrypted-shots.json", "path: ~/.cache/u1-shots/scai-meet-plugin/ci/**/*.png"],
    ["path: ${{ runner.temp }}/scai-revenue-browser-encrypted-shots.json", "path: ${{ runner.temp }}/scai-revenue-browser-proof/"],
  ]) {
    assert.ok(fixtures["pr-check.yml"].includes(before), before);
    const errors = validateSourceConfidentiality({ ...fixtures, "pr-check.yml": fixtures["pr-check.yml"].replace(before, after) }, assetSelector);
    assert.ok(errors.includes("pr-check.yml: proof screenshots must never be uploaded in plaintext (public repository)"), after);
  }
});

test("u1-chat test diagnostics reject missing keys, public plaintext and broad uploads", () => {
  const name = "u1-chat-pr-check.yml";
  const cases = [
    ["missing key", "SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64: ${{ inputs.diagnostic_public_key_base64 }}", "SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64: ''"],
    ["plaintext", "path: ${{ runner.temp }}/u1-chat-diagnostic.json", "path: ${{ runner.temp }}/scai-confidential-logs/"],
    ["wildcard", "path: ${{ runner.temp }}/u1-chat-diagnostic.json", "path: ${{ runner.temp }}/u1-chat-*"],
    ["unconditional upload", "if: failure() && steps.backend_tests.outcome == 'failure' && inputs.diagnostic_public_key_base64 != ''", "if: always()"],
    ["stale success envelope", "if: failure() && steps.backend_tests.outcome == 'failure' && inputs.diagnostic_public_key_base64 != ''", "if: failure() && inputs.diagnostic_public_key_base64 != ''"],
    ["long retention", "retention-days: 1", "retention-days: 90"],
  ];
  for (const [label, before, after] of cases) {
    assert.ok(fixtures[name].includes(before), label);
    const errors = validateSourceConfidentiality({ ...fixtures, [name]: fixtures[name].replace(before, after) }, assetSelector);
    assert.ok(errors.some((error) => error.startsWith("u1-chat-pr-check.yml:")), label);
  }
  for (const decoder of ["pdfinfo", "djpeg", "pngcheck", "jq"]) {
    const errors = validateSourceConfidentiality({ ...fixtures, [name]: fixtures[name].replace(`command -v ${decoder}`, "true") }, assetSelector);
    assert.ok(errors.some((error) => error.endsWith(`not checked: ${decoder}`)), decoder);
  }
});

test("u1-chat backend suites retain per-file isolation without test filters", () => {
  for (const name of ["u1-chat-pr-check.yml", "fleet-source-check.yml"]) {
    const missingIsolation = {
      ...fixtures,
      [name]: fixtures[name].replace("u1-chat-tests bun test --isolate", "u1-chat-tests bun test"),
    };
    assert.match(validateSourceConfidentiality(missingIsolation, assetSelector).join("\n"), new RegExp(`${name.replaceAll(".", "\\.")}: u1-chat backend suite`));

    const filteredSuite = {
      ...fixtures,
      [name]: fixtures[name].replace("u1-chat-tests bun test --isolate", "u1-chat-tests bun test test/server.test.ts --isolate"),
    };
    assert.match(validateSourceConfidentiality(filteredSuite, assetSelector).join("\n"), new RegExp(`${name.replaceAll(".", "\\.")}: u1-chat backend suite`));
  }
});

for (const declaration of [
  '      replica: { image: postgres:fixture, options: "--health-cmd pg_isready" }',
  '      "replica":\n        image: postgres:fixture',
  '      replica: *unprotected-service',
  '      <<: *unprotected-services',
]) {
  test(`unsupported service declaration cannot evade log protection: ${declaration.split("\n")[0].trim()}`, () => {
    const unsafe = { ...fixtures, "auth-pr-check.yml": fixtures["auth-pr-check.yml"].replace("    services:\n", `    services:\n${declaration}\n`) };
    assert.match(validateSourceConfidentiality(unsafe, assetSelector).join("\n"), /auth-pr-check\.yml: every private service options/);
  });
}

test("a second job cannot hide service logging behind a flow mapping", () => {
  const unsafe = { ...fixtures, "auth-pr-check.yml": fixtures["auth-pr-check.yml"] + '\n  another-private-job:\n    services: { postgres: { image: postgres:fixture } }\n' };
  assert.match(validateSourceConfidentiality(unsafe, assetSelector).join("\n"), /auth-pr-check\.yml: every private service options/);
});

for (const servicesKey of ['"services":', "services :"]) {
  test(`a second job cannot hide services behind non-canonical key syntax: ${servicesKey}`, () => {
    const unsafe = {
      ...fixtures,
      "auth-pr-check.yml": `${fixtures["auth-pr-check.yml"]}\n  another-private-job:\n    ${servicesKey}\n      replica:\n        image: postgres:fixture\n`,
    };
    assert.match(validateSourceConfidentiality(unsafe, assetSelector).join("\n"), /auth-pr-check\.yml: every private service options/);
  });
}

for (const mutation of [
  ['quoted root jobs key', /^jobs:/m, '"jobs":'],
  ['quoted job key', /^  consent-dsar:/m, '  "consent-dsar":'],
  ['job alias', /^  consent-dsar:/m, '  consent-dsar: *private-job'],
  ['root merge key', /^jobs:/m, '<<: *private-root\njobs:'],
  ['job merge key', /^    runs-on:/m, '    <<: *private-job\n    runs-on:'],
  ['quoted options key', /^        options:/m, '        "options":'],
  ['service-attribute merge key', /^        image:/m, '        <<: *private-service\n        image:'],
]) {
  test(`private workflow structure rejects ${mutation[0]}`, () => {
    const source = fixtures["auth-pr-check.yml"];
    const changed = source.replace(mutation[1], mutation[2]);
    assert.notEqual(changed, source, `fixture mutation for ${mutation[0]} must apply`);
    const unsafe = { ...fixtures, "auth-pr-check.yml": changed };
    assert.match(validateSourceConfidentiality(unsafe, assetSelector).join("\n"), /auth-pr-check\.yml: every private service options/);
  });
}

test("run block scalar contents are not interpreted as workflow structure", () => {
  const source = fixtures["auth-pr-check.yml"];
  const changed = source.replace(
    "          set -euo pipefail\n",
    `          set -euo pipefail
          printf '%s\\n' '"jobs":' 'services : hidden' '<<: *shell' '"options": hidden'
`,
  );
  assert.notEqual(changed, source, "run block fixture mutation must apply");
  assert.deepEqual(validateSourceConfidentiality({ ...fixtures, "auth-pr-check.yml": changed }, assetSelector), []);
});

for (const name of ["auth-pr-check.yml", "atlas-pr-check.yml", "fleet-source-check.yml"]) {
  test(`${name} PostgreSQL service cannot expose its teardown log`, () => {
    const unsafe = { ...fixtures, [name]: fixtures[name].replace(/^\s+--log-driver none\s*$/m, "") };
    assert.match(validateSourceConfidentiality(unsafe, assetSelector).join("\n"), new RegExp(`${name.replace(".", "\\.")}: every private service options`));
  });
}

test("a commented or wrong-service log driver cannot satisfy the PostgreSQL boundary", () => {
  const commented = {
    ...fixtures,
    "auth-pr-check.yml": fixtures["auth-pr-check.yml"].replace("          --log-driver none", "          # --log-driver none"),
  };
  assert.match(validateSourceConfidentiality(commented, assetSelector).join("\n"), /auth-pr-check\.yml: every private service options/);

  const wrongService = {
    ...fixtures,
    "atlas-pr-check.yml": fixtures["atlas-pr-check.yml"]
      .replace("          --log-driver none\n", "")
      .replace("    services:\n", "    services:\n      redis:\n        image: redis:fixture\n        options: >-\n          --log-driver none\n"),
  };
  assert.match(validateSourceConfidentiality(wrongService, assetSelector).join("\n"), /atlas-pr-check\.yml: every private service options/);

  const commandText = {
    ...fixtures,
    "auth-pr-check.yml": fixtures["auth-pr-check.yml"]
      .replace("          --log-driver none\n", "")
      .replace("          --health-cmd pg_isready", '          --health-cmd "echo --log-driver none"'),
  };
  assert.match(validateSourceConfidentiality(commandText, assetSelector).join("\n"), /auth-pr-check\.yml: every private service options/);
});

test("a differently named PostgreSQL replica cannot bypass private service log suppression", () => {
  const unsafe = {
    ...fixtures,
    "auth-pr-check.yml": fixtures["auth-pr-check.yml"].replace(
      "    services:\n",
      `    services:
      replica:
        image: postgres@sha256:95206741a5b214807675e14165369d05b93a9cf692223b616d07cca227e74b0b
        options: >-
          --health-cmd pg_isready
`,
    ),
  };
  assert.match(validateSourceConfidentiality(unsafe, assetSelector).join("\n"), /auth-pr-check\.yml: every private service options/);
});

for (const hiddenFlag of [
  '--log-driver\n          json-file',
  '"--log-driver" json-file',
  '--log-\\driver json-file',
  '${{ inputs.extra_service_options }}',
]) {
  test(`non-canonical service arguments cannot hide a second log driver: ${hiddenFlag}`, () => {
    const unsafe = {
      ...fixtures,
      "auth-pr-check.yml": fixtures["auth-pr-check.yml"].replace(
        "          --log-driver none",
        `          --log-driver none\n          ${hiddenFlag}`,
      ),
    };
    assert.match(validateSourceConfidentiality(unsafe, assetSelector).join("\n"), /auth-pr-check\.yml: every private service options/);
  });
}

test("duplicate or overriding PostgreSQL log drivers fail closed", () => {
  const duplicateDriver = {
    ...fixtures,
    "fleet-source-check.yml": fixtures["fleet-source-check.yml"].replace("          --log-driver none", "          --log-driver none\n          --log-driver json-file"),
  };
  assert.match(validateSourceConfidentiality(duplicateDriver, assetSelector).join("\n"), /fleet-source-check\.yml: every private service options/);

  const duplicateOptions = {
    ...fixtures,
    "auth-pr-check.yml": fixtures["auth-pr-check.yml"].replace("          --health-retries 12", "          --health-retries 12\n        options: --log-driver json-file"),
  };
  assert.match(validateSourceConfidentiality(duplicateOptions, assetSelector).join("\n"), /auth-pr-check\.yml: every private service options/);
});

test("an automatic public trigger is rejected", () => {
  const unsafe = { ...fixtures, "pr-check.yml": fixtures["pr-check.yml"].replace("  workflow_dispatch:", "  pull_request:\n  workflow_dispatch:") };
  assert.match(validateSourceConfidentiality(unsafe, assetSelector).join("\n"), /must not have an automatic or fork trigger/);
});

test("a PR check without its exact source identity in the run name is rejected", () => {
  const unsafe = { ...fixtures, "pr-check.yml": fixtures["pr-check.yml"].replace("run-name: SCAI PR · ${{ inputs.ref }} · ${{ inputs.request_id }}\n", "") };
  assert.match(validateSourceConfidentiality(unsafe, assetSelector).join("\n"), /exact private source ref/);
});

const sourceSha = "a".repeat(40);
const requestId = "e95aacd2-45ab-4e0b-9cff-bb7c015b1f90";
const traceSha = "b".repeat(40);

test("preflight preserves exact source/request binding, including all UUIDv4 variants", () => {
  for (const variant of ["8", "9", "a", "b"]) {
    const id = requestId.slice(0, 19) + variant + requestId.slice(20);
    assert.deepEqual(validatePrRequest(sourceSha, id, traceSha, "public-recipient"), {
      source_sha: sourceSha, request_id: id, trace_sha: traceSha,
    });
  }
  assert.equal(validatePrRequest(sourceSha, requestId).trace_sha, "");
});

for (const [label, patch] of [
  ["missing source", { SOURCE_SHA: "" }],
  ["mutable source", { SOURCE_SHA: "main" }],
  ["short source", { SOURCE_SHA: sourceSha.slice(1) }],
  ["uppercase source", { SOURCE_SHA: sourceSha.toUpperCase() }],
  ["newline source", { SOURCE_SHA: sourceSha + "\n" }],
  ["shell source", { SOURCE_SHA: "$(touch must-not-execute)" }],
  ["missing request", { REQUEST_ID: "" }],
  ["uppercase request", { REQUEST_ID: requestId.toUpperCase() }],
  ["UUIDv1", { REQUEST_ID: requestId.replace("-4e0b-", "-1e0b-") }],
  ["non-RFC variant", { REQUEST_ID: requestId.replace("-9cff-", "-7cff-") }],
  ["trailing space", { REQUEST_ID: requestId + " " }],
  ["trailing newline", { REQUEST_ID: requestId + "\n" }],
  ["output injection", { REQUEST_ID: requestId + "\nsource_sha=foreign" }],
  ["mutable Trace", { TRACE_SHA: "main" }],
  ["newline Trace", { TRACE_SHA: traceSha + "\n" }],
  ["bundle without Trace", { TRACE_BUNDLE_KEY: "public-recipient" }],
]) {
  test(`real preflight rejects ${label} before writing any downstream output`, () => {
    const dir = mkdtempSync(join(tmpdir(), "source-request-policy-"));
    try {
      const output = join(dir, "output");
      const result = spawnSync(process.execPath, [join(ROOT, "scripts/verify-source-confidentiality.mjs"), "--pr-request"], {
        cwd: dir, encoding: "utf8", timeout: 10000,
        env: { PATH: process.env.PATH, SOURCE_SHA: sourceSha, REQUEST_ID: requestId, TRACE_SHA: "", TRACE_BUNDLE_KEY: "", GITHUB_OUTPUT: output, ...patch },
      });
      assert.equal(result.status, 1, result.stderr);
      assert.match(result.stderr, /^FAIL /);
      assert.equal(result.stdout, "");
      assert.equal(existsSync(output), false);
      assert.equal(existsSync(join(dir, "must-not-execute")), false);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
}

test("the actual workflow preflight command emits only validated job outputs", () => {
  const workflow = fixtures["pr-check.yml"];
  assert.match(workflow, /run: node gate\/scripts\/verify-source-confidentiality\.mjs --pr-request/);
  const dir = mkdtempSync(join(tmpdir(), "source-request-policy-"));
  try {
    const output = join(dir, "output");
    const result = spawnSync(process.execPath, [join(ROOT, "scripts/verify-source-confidentiality.mjs"), "--pr-request"], {
      cwd: dir, encoding: "utf8", timeout: 10000,
      env: { PATH: process.env.PATH, SOURCE_SHA: sourceSha, REQUEST_ID: requestId, TRACE_SHA: traceSha, TRACE_BUNDLE_KEY: "public-recipient", GITHUB_OUTPUT: output },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(readFileSync(output, "utf8"), `source_sha=${sourceSha}\nrequest_id=${requestId}\ntrace_sha=${traceSha}\n`);
    assert.match(result.stdout, new RegExp(`source-sha=${sourceSha}, request-id=${requestId}`));
    assert.ok(!result.stdout.includes("public-recipient"));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

function rejectPrMutation(label, mutate, expected) {
  test(`request/gate policy rejects ${label}`, () => {
    const source = fixtures["pr-check.yml"];
    const changed = mutate(source);
    assert.notEqual(changed, source, "negative mutation must really alter the workflow");
    assert.match(validateSourceConfidentiality({ ...fixtures, "pr-check.yml": changed }, assetSelector).join("\n"), expected);
  });
}

const rustSetupStep = `      - name: Rust für compilerführende Frontendtests einrichten
        uses: dtolnay/rust-toolchain@4360b52568e2003a75bf9bc1d59f33a8e3fc893c # stable, immutable
        timeout-minutes: 5`;
const rustReadyStep = `      - name: Rust-Compiler vor privaten Tests prüfen
        shell: bash
        timeout-minutes: 2
        run: rustc --version --verbose`;
for (const [label, mutate] of [
  ["missing Rust setup", (source) => source.replace(rustSetupStep, "")],
  ["duplicate Rust setup", (source) => source.replace(rustSetupStep, `${rustSetupStep}\n\n${rustSetupStep}`)],
  ["skipped Rust setup", (source) => source.replace(rustSetupStep, `${rustSetupStep}\n        if: false`)],
  ["ignored Rust setup failure", (source) => source.replace(rustSetupStep, `${rustSetupStep}\n        continue-on-error: true`)],
  ["missing compiler readiness", (source) => source.replace(rustReadyStep, "")],
  ["ignored compiler readiness failure", (source) => source.replace(rustReadyStep, `${rustReadyStep} || true`)],
  ["unbounded compiler readiness", (source) => source.replace(rustReadyStep, rustReadyStep.replace("        timeout-minutes: 2\n", ""))],
  ["readiness before setup", (source) => source.replace(rustSetupStep, rustReadyStep).replace(`${rustReadyStep}\n\n      # Klon`, `${rustSetupStep}\n\n      # Klon`)],
  ["Rust setup only after frontend tests", (source) => source.replace(rustSetupStep, "").replace(rustReadyStep, "").replace("      - name: Tauri-Systemabhängigkeiten", `${rustSetupStep}\n\n${rustReadyStep}\n\n      - name: Tauri-Systemabhängigkeiten`)],
]) rejectPrMutation(label, mutate, /Rust setup and bounded compiler readiness/);

for (const [label, from, to, error] of [
  ["legacy run name", " · ${{ inputs.request_id }}\n", "\n", /run name/],
  ["optional request", '        description: "Neue eindeutige UUIDv4 für diesen Source-Prüfauftrag"\n        required: true', '        description: "Request"\n        required: false', /request_id must be/],
  ["request default", "      request_id:\n", "      request_id:\n        default: fixed\n", /request_id must be/],
  ["duplicate request requirement", "        type: string\n      trace_ref:", "        type: string\n        required: false\n      trace_ref:", /request_id must be/],
  ["source default", "      ref:\n", "      ref:\n        default: main\n", /ref must be/],
  ["source-only concurrency", '  group: pr-check-${{ inputs.ref }}-${{ inputs.request_id }}', '  group: pr-check-${{ inputs.ref }}', /concurrency/],
  ["cancelling running proofs", "  cancel-in-progress: false", "  cancel-in-progress: true", /concurrency/],
  ["skipped preflight", "  preflight:\n", "  preflight:\n    if: false\n", /preflight must/],
  ["ignored preflight failure", "  preflight:\n", "  preflight:\n    continue-on-error: true\n", /preflight must/],
  ["secret in preflight", "          SOURCE_SHA: ${{ inputs.ref }}", "          SOURCE_SHA: ${{ secrets.SOURCE_DEPLOY_KEY }}", /preflight must/],
  ["forged source output", "source_sha: ${{ steps.request.outputs.source_sha }}", "source_sha: ${{ inputs.ref }}", /preflight must/],
  ["preflight without validator", "run: node gate/scripts/verify-source-confidentiality.mjs --pr-request", "run: true", /preflight must/],
  ["input embedded in shell", "run: node gate/scripts/verify-source-confidentiality.mjs --pr-request", "run: echo '${{ inputs.request_id }}'", /preflight must/],
  ["global secret env", "jobs:\n", "env:\n  KEY: ${{ secrets.SOURCE_DEPLOY_KEY }}\njobs:\n", /canonical unique/],
  ["duplicate job key", "  check:\n", "  check:\n    runs-on: ubuntu-latest\n  check:\n", /canonical unique|dependency graph/],
  ["new unguarded private job", "jobs:\n", "jobs:\n  surprise:\n    runs-on: ubuntu-latest\n    env:\n      KEY: ${{ secrets.SOURCE_DEPLOY_KEY }}\n", /dependency graph/],
  ["quoted job bypass", "  native-trace:\n", '  "native-trace":\n', /canonical unique|dependency graph/],
]) rejectPrMutation(label, (source) => source.replace(from, to), error);

for (const job of ["check", "trace-standalone", "native-trace"]) {
  for (const [label, from, to, error] of [
    ["missing dependency", "    needs: preflight\n", "", /successful preflight/],
    ["always despite failed preflight", "needs.preflight.result == 'success'", "always()", /successful preflight/],
    ["continue-on-error", `  ${job}:\n`, `  ${job}:\n    continue-on-error: true\n`, /successful preflight/],
    ["unvalidated source", "SRC_REF: ${{ needs.preflight.outputs.", "SRC_REF: ${{ inputs.", /validated source\/request/],
    ["unvalidated request", "REQUEST_ID: ${{ needs.preflight.outputs.request_id }}", "REQUEST_ID: ${{ inputs.request_id }}", /validated source\/request/],
  ]) rejectPrMutation(`${job} ${label}`, (source) => source.replace(new RegExp(`^  ${job}:\\n[\\s\\S]*?(?=^  [\\w-]+:|$(?![\\s\\S]))`, "m"), (block) => block.replace(from, to)), error);
}

for (const [label, command] of [
  ["web-release-fixture-tests", "npm run test:web"],
  ["plugin-deploy-tests", "npm run test:plugin-deploy"],
  ["host-restore-webkit-proof", "node scripts/verify-pages-foundation.mjs"],
]) {
  for (const [mutation, replace] of [
    ["missing", () => "        run: true"],
    ["unwrapped", () => `        run: ${command}`],
    ["soft failure", (line) => line + " || true"],
    ["skipped", (line) => `        if: false\n${line}`],
    ["ignored failure", (line) => `        continue-on-error: true\n${line}`],
    ["comment-only command", (line) => `        # ${line.trim()}\n        run: true`],
  ]) rejectPrMutation(`${label} ${mutation}`, (source) => source.replace(new RegExp(`^        run: .* ${label} .*$`, "m"), replace), /confidential.*(?:gate|source)/);
}

for (const [label, from, to] of [
  ["Chromium instead of WebKit", "PAGES_PROOF_BROWSER: webkit", "PAGES_PROOF_BROWSER: chromium"],
  ["missing host focus", "          PAGES_PROOF_FOCUS: host-restore\n", ""],
  ["only one viewport", "          PAGES_PROOF_FOCUS: host-restore", "          PAGES_PROOF_FOCUS: host-restore\n          PAGES_PROOF_VARIANT: light-390"],
  ["overwriting normal Pages output", "PAGES_PROOF_OUT: ${{ runner.temp }}/scai-host-restore-webkit", "PAGES_PROOF_OUT: ~/.cache/u1-shots/scai-pages"],
  ["missing WebKit deps", "install --with-deps chromium webkit", "install chromium"],
  ["raw WebKit upload", "path: ${{ runner.temp }}/scai-host-restore-webkit-diagnostic.json", "path: ${{ runner.temp }}/scai-host-restore-webkit/"],
  ["WebKit upload path suffix", "path: ${{ runner.temp }}/scai-host-restore-webkit-diagnostic.json", "path: ${{ runner.temp }}/scai-host-restore-webkit-diagnostic.json/../scai-host-restore-webkit/"],
  ["second raw WebKit upload", "          path: ${{ runner.temp }}/scai-host-restore-webkit-diagnostic.json", "          path: ${{ runner.temp }}/scai-host-restore-webkit-diagnostic.json\n          path: src/"],
  ["unkeyed WebKit diagnostic", "if: failure() && steps.host_restore_webkit.outcome == 'failure' && inputs.diagnostic_public_key_base64 != ''", "if: failure()"],
]) rejectPrMutation(label, (source) => source.replace(from, to), /WebKit/);

test("a mutable action can never run beside private source", () => {
  const unsafe = { ...fixtures, "windows-arm-smoke.yml": fixtures["windows-arm-smoke.yml"].replace(/actions\/setup-node@[0-9a-f]{40}/, "actions/setup-node@v4") };
  assert.match(validateSourceConfidentiality(unsafe, assetSelector).join("\n"), /action reference must be immutable/);

  const shorthand = { ...fixtures, "pr-check.yml": fixtures["pr-check.yml"].replace(/- uses: dtolnay\/rust-toolchain@[0-9a-f]{40}/, "- uses: dtolnay/rust-toolchain@stable") };
  assert.match(validateSourceConfidentiality(shorthand, assetSelector).join("\n"), /action reference must be immutable/);
});

test("a mutable branch clone cannot stand in for an exact source pin", () => {
  const unsafe = { ...fixtures, "pr-check.yml": fixtures["pr-check.yml"].replace('git -C src fetch --depth 1 -- origin "$SRC_REF"', 'git clone --depth 1 --branch "$SRC_REF" git@github.com:subunit-ai/subunit-scai.git src') };
  assert.match(validateSourceConfidentiality(unsafe, assetSelector).join("\n"), /mutable branch clone/);
});

test("private source fetches must terminate options before the validated ref", () => {
  const unsafe = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace(
      'git -C src fetch --depth 1 -- origin "$SRC_REF"',
      'git -C src fetch --depth 1 origin "$SRC_REF"',
    ),
  };
  assert.match(
    validateSourceConfidentiality(unsafe, assetSelector).join("\n"),
    /source fetch must terminate options|must not accept ref-shaped options/,
  );
});

test("source ref validation must run before deploy-key material is created", () => {
  const validation = 'bash "$GITHUB_WORKSPACE/gate/scripts/validate-private-source-ref.sh" "$SRC_REF"';
  const keyWrite = 'printf \'%s\\n\' "$DEPLOY_KEY" > "$key_file"';
  const unsafeWorkflow = fixtures["pr-check.yml"]
    .replace(validation, "true")
    .replace(keyWrite, `${keyWrite}\n          ${validation}`);
  const unsafe = { ...fixtures, "pr-check.yml": unsafeWorkflow };
  assert.match(
    validateSourceConfidentiality(unsafe, assetSelector).join("\n"),
    /allowlist-validated before deploy-key material is created/,
  );
});

test("a source-streaming Tauri action is rejected", () => {
  const unsafe = { ...fixtures, "build-all.yml": `${fixtures["build-all.yml"]}\n      - uses: tauri-apps/tauri-action@${"a".repeat(40)}\n` };
  assert.match(validateSourceConfidentiality(unsafe, assetSelector).join("\n"), /tauri-action may expose private compiler output/);
});

test("private build outputs cannot enter a public Actions cache", () => {
  const unsafe = {
    ...fixtures,
    "pr-check.yml": `${fixtures["pr-check.yml"]}\n      - uses: swatinem/rust-cache@${"a".repeat(40)}\n`,
  };
  assert.match(validateSourceConfidentiality(unsafe, assetSelector).join("\n"), /private build outputs must not enter a public Actions cache/);
});

test("an internal Trace bundle can leave the public runner only as a keyed encrypted envelope", () => {
  const plaintextUpload = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace(
      "path: ${{ runner.temp }}/trace-host-macos-arm64-internal.tar.gz.envelope.json",
      "path: ${{ runner.temp }}/trace-host-macos-arm64-internal.tar.gz",
    ),
  };
  assert.match(
    validateSourceConfidentiality(plaintextUpload, assetSelector).join("\n"),
    /encrypted envelope|plaintext Trace delivery archives/,
  );

  const missingKeyGate = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replaceAll(
      "inputs.trace_bundle_public_key_base64 != ''",
      "always()",
    ),
  };
  assert.match(
    validateSourceConfidentiality(missingKeyGate, assetSelector).join("\n"),
    /explicit one-time recipient key|encrypted envelope/,
  );

  const sourceAfterSecrets = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace(
      "name: Signierten Trace-App-Bundle bauen und einmalig verschlüsseln",
      "name: Signierten Trace-App-Bundle bauen und einmalig verschlüsseln\n        run-private-after-import: bash scripts/build-macos-app.sh",
    ),
  };
  assert.match(
    validateSourceConfidentiality(sourceAfterSecrets, assetSelector).join("\n"),
    /no private Trace packaging script may execute after signing secrets/,
  );

  const setupAfterSecrets = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace(
      "name: Signierten Trace-App-Bundle bauen und einmalig verschlüsseln",
      "name: Signierten Trace-App-Bundle bauen und einmalig verschlüsseln\n        run-private-after-import: bash scripts/build-macos-setup-app.sh",
    ),
  };
  assert.match(
    validateSourceConfidentiality(setupAfterSecrets, assetSelector).join("\n"),
    /no private Trace setup packaging script may execute after signing secrets/,
  );

  const missingSetupIdentity = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace(
      'setup_bundle_identifier:"ai.subunit.trace-setup"',
      'setup_bundle_identifier:"unknown"',
    ),
  };
  assert.match(
    validateSourceConfidentiality(missingSetupIdentity, assetSelector).join("\n"),
    /setup app must be identity-bound/,
  );
});

test("Bun setup cannot run after the private source checkout", () => {
  const action = fixtures["pr-check.yml"].match(/\n      # Bun wird[\s\S]*?uses: oven-sh\/setup-bun@[0-9a-f]{40}[^\n]*\n/)?.[0];
  assert.ok(action);
  const withoutAction = fixtures["pr-check.yml"].replace(action, "\n");
  const sourceStep = "      - name: Quellcode auschecken (privates Repo, read-only Deploy-Key)";
  const unsafe = {
    ...fixtures,
    "pr-check.yml": withoutAction.replace(sourceStep, `${sourceStep}${action}`),
  };
  assert.match(
    validateSourceConfidentiality(unsafe, assetSelector).join("\n"),
    /Bun setup must complete before private source checkout/,
  );
});

test("a broad upload cannot replace the release artifact allowlist", () => {
  const unsafe = { ...fixtures, "build-all.yml": fixtures["build-all.yml"].replace('upload-draft-assets.sh" "${ASSETS[@]}"', 'upload-draft-assets.sh" "$BUNDLE_ROOT"') };
  assert.match(validateSourceConfidentiality(unsafe, assetSelector).join("\n"), /validated asset array/);
});

test("a widened release filename allowlist is rejected", () => {
  const unsafeSelector = assetSelector.replace("*.dmg|", "*.rs|*.dmg|");
  assert.match(validateSourceConfidentiality(fixtures, unsafeSelector).join("\n"), /closed filename allowlist/);
});

test("Windows ARM diagnostics cannot upload plaintext or a source-tree path", () => {
  const unsafe = {
    ...fixtures,
    "windows-arm-smoke.yml": fixtures["windows-arm-smoke.yml"].replace(
      "path: ${{ runner.temp }}/scai-arm64-diagnostic.json",
      "path: src/private-build.log",
    ),
  };
  assert.match(validateSourceConfidentiality(unsafe, assetSelector).join("\n"), /only a one-time-key encrypted envelope/);
});

test("Trace Windows diagnostics cannot upload plaintext or a source-tree path", () => {
  const unsafe = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace(
      "path: ${{ runner.temp }}/trace-windows-diagnostic.json",
      "path: trace-src/private-clippy.log",
    ),
  };
  assert.match(validateSourceConfidentiality(unsafe, assetSelector).join("\n"), /Trace Windows diagnostics may upload only a one-time-key encrypted envelope/);
});

test("Pages diagnostics cannot upload plaintext or a source-tree path", () => {
  const unsafe = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace(
      "path: ${{ runner.temp }}/scai-pages-diagnostic.json",
      "path: src/private-pages.log",
    ),
  };
  assert.match(validateSourceConfidentiality(unsafe, assetSelector).join("\n"), /Pages diagnostics may upload only a one-time-key encrypted envelope/);
});

// CI 40208997675 dispatched a recipient, but the web fixture step received no
// encryption env and had no upload. Bind this exact mandatory gate end to end.
const webFixtureProofName = "Web- und Release-Fixture-Verträge prüfen";
const webFixtureUploadName = "Verschlüsselte Web-/Release-Fixture-Fehlerdiagnostik bereitstellen";
function webFixtureDiagnosticMutation(transform) {
  const source = fixtures["pr-check.yml"];
  const start = source.indexOf(`      - name: ${webFixtureProofName}\n`);
  const end = source.indexOf("      - name: Plugin-Deploy-Snapshot und Fehlergrenzen prüfen\n", start);
  assert.ok(start >= 0 && end > start);
  const block = source.slice(start, end); const changed = transform(block);
  assert.notEqual(changed, block, "mutation must change the real workflow");
  return { ...fixtures, "pr-check.yml": source.slice(0, start) + changed + source.slice(end) };
}

test("web fixture diagnostic has exactly one mandatory producer and failed-step encrypted upload", () => {
  assert.match(meetStep(webFixtureProofName), /^        id: web_release_fixture_tests$/m);
  assert.match(meetStep(webFixtureUploadName), /^          retention-days: 1$/m);
  assert.deepEqual(validateSourceConfidentiality(fixtures, assetSelector), []);
});

for (const [label, transform] of [
  ["missing id", block => block.replace("        id: web_release_fixture_tests\n", "")],
  ["missing recipient env", block => block.replace(/^          SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64:.*\n/m, "")],
  ["missing diagnostic path", block => block.replace(/^          SCAI_ENCRYPTED_DIAGNOSTIC_PATH:.*\n/m, "")],
  ["mismatched diagnostic path", block => block.replace("format('{0}/scai-web-release-fixture-diagnostic.json', runner.temp)", "format('{0}/wrong-diagnostic.json', runner.temp)")],
  ["missing upload", block => block.slice(0, block.indexOf(`      - name: ${webFixtureUploadName}\n`))],
  ["wrong failed step", block => block.replace("steps.web_release_fixture_tests.outcome", "steps.frontend_unit_tests.outcome")],
  ["upload without recipient guard", block => block.replace(" && inputs.diagnostic_public_key_base64 != ''\n", "\n")],
  ["unconditional upload", block => block.replace(/^        if: failure\(\).*$/m, "        if: always()")],
  ["raw output upload", block => block.replace("path: ${{ runner.temp }}/scai-web-release-fixture-diagnostic.json", "path: src/private-test.log")],
  ["mutable upload action", block => block.replace("actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02", "actions/upload-artifact@v4")],
  ["long retention", block => block.replace("retention-days: 1", "retention-days: 90")],
  ["missing envelope tolerated", block => block.replace("if-no-files-found: error", "if-no-files-found: warn")],
  ["upload failure ignored", block => block.replace(`- name: ${webFixtureUploadName}\n`, `- name: ${webFixtureUploadName}\n        continue-on-error: true\n`)],
  ["duplicate upload", block => block + block.slice(block.indexOf(`      - name: ${webFixtureUploadName}\n`)).replace(webFixtureUploadName, "Duplicate web fixture upload")],
]) test(`web fixture diagnostic rejects ${label}`, () => {
  assert.match(validateSourceConfidentiality(webFixtureDiagnosticMutation(transform), assetSelector).join("\n"), /Web\/release fixture diagnostics/);
});

test("Frontend unit diagnostics require the supplied key and exact encrypted envelope", () => {
  const expected = /Frontend unit diagnostics (?:must stay confidential and use the supplied one-time key|may upload only the keyed one-day encrypted envelope, never raw test output)/;
  const cases = [
    fixtures["pr-check.yml"].replace(
      "if: failure() && steps.frontend_unit_tests.outcome == 'failure' && inputs.diagnostic_public_key_base64 != ''",
      "if: failure() && steps.frontend_unit_tests.outcome == 'failure'",
    ),
    fixtures["pr-check.yml"].replace(
      "path: ${{ runner.temp }}/scai-frontend-unit-diagnostic.json",
      "path: src/private-frontend-unit.log",
    ),
    fixtures["pr-check.yml"].replace(
      "SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64: ${{ inputs.diagnostic_public_key_base64 }}",
      "SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64:",
    ),
    fixtures["pr-check.yml"].replace(
      "if: failure() && steps.frontend_unit_tests.outcome == 'failure' && inputs.diagnostic_public_key_base64 != ''",
      "if: success() && steps.frontend_unit_tests.outcome == 'failure' && inputs.diagnostic_public_key_base64 != ''",
    ),
    fixtures["pr-check.yml"].replace(
      "          if-no-files-found: error\n          retention-days: 1\n\n      - name: Web",
      "          if-no-files-found: error\n\n      - name: Web",
    ),
    fixtures["pr-check.yml"].replace(
      "          retention-days: 1\n\n      - name: Web- und Release-Fixture-Verträge prüfen",
      `          retention-days: 1

      - name: Raw Frontend unit diagnostic
        uses: actions/upload-artifact@${"a".repeat(40)}
        with:
          name: scai-frontend-unit-raw-\${{ github.run_id }}
          path: \${{ runner.temp }}/scai-frontend-unit/
          if-no-files-found: error
          retention-days: 1

      - name: Web- und Release-Fixture-Verträge prüfen`,
    ),
    fixtures["pr-check.yml"].replace(
      '        run: bash "$GITHUB_WORKSPACE/gate/scripts/run-confidential.sh" frontend-unit-tests bun test src/lib',
      '        # run: bash "$GITHUB_WORKSPACE/gate/scripts/run-confidential.sh" frontend-unit-tests bun test src/lib\n        run: true',
    ),
  ];
  for (const workflow of cases) {
    assert.match(
      validateSourceConfidentiality({ ...fixtures, "pr-check.yml": workflow }, assetSelector).join("\n"),
      expected,
    );
  }
});

test("Chat-Dock proof cannot upload the private source tree", () => {
  const unsafe = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace(
      'dir="$HOME/.cache/u1-shots/scai-chat-dock"',
      'dir="src"',
    ),
  };
  assert.match(
    validateSourceConfidentiality(unsafe, assetSelector).join("\n"),
    /Chat-Dock proof may upload only its encrypted screenshot envelope/,
  );
});

test("Sentinel CRM proof cannot upload the private source tree", () => {
  const unsafe = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace(
      'dir="$HOME/.cache/u1-shots/sentinel-crm-2026"',
      'dir="src"',
    ),
  };
  assert.match(
    validateSourceConfidentiality(unsafe, assetSelector).join("\n"),
    /Sentinel CRM proof may upload only its encrypted screenshot envelope/,
  );
});

test("Sentinel CRM diagnostics cannot upload plaintext or a source-tree path", () => {
  const unsafe = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace(
      "path: ${{ runner.temp }}/scai-sentinel-crm-diagnostic.json",
      "path: src/private-sentinel-crm.log",
    ),
  };
  assert.match(
    validateSourceConfidentiality(unsafe, assetSelector).join("\n"),
    /Sentinel CRM diagnostics may upload only a one-time-key encrypted envelope/,
  );
});

test("Sentinel Routing failures require a one-time-key envelope, never plaintext", () => {
  const missingKey = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace(
      "SCAI_ENCRYPTED_DIAGNOSTIC_PATH: ${{ inputs.diagnostic_public_key_base64 != '' && format('{0}/scai-sentinel-routing-diagnostic.json', runner.temp) || '' }}",
      "SCAI_ENCRYPTED_DIAGNOSTIC_PATH: ''",
    ),
  };
  assert.match(
    validateSourceConfidentiality(missingKey, assetSelector).join("\n"),
    /Sentinel Routing proof must seal private failures with the supplied one-time key/,
  );

  const plaintext = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace(
      "path: ${{ runner.temp }}/scai-sentinel-routing-diagnostic.json",
      "path: src/private-sentinel-routing.log",
    ),
  };
  assert.match(
    validateSourceConfidentiality(plaintext, assetSelector).join("\n"),
    /Sentinel Routing diagnostics may upload only a one-time-key encrypted envelope/,
  );
});

test("Revenue harnesses cannot be partially present or bypass confidential execution", () => {
  const partialAllowed = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace(
      `            echo "::error::Revenue-Browser-Proof ist unvollständig; Billing- und Offers-Harness müssen gemeinsam vorliegen."
            exit 1`,
      '            echo "revenue_browser=false" >> "$GITHUB_OUTPUT"',
    ),
  };
  assert.match(
    validateSourceConfidentiality(partialAllowed, assetSelector).join("\n"),
    /partial Revenue harness availability must fail closed/,
  );

  const publicHarness = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace("billing-production-proof", "billing-public-proof"),
  };
  assert.match(
    validateSourceConfidentiality(publicHarness, assetSelector).join("\n"),
    /billing-production-proof must suppress private output/,
  );
});

test("Workspace browser harnesses are an atomic confidential gate", () => {
  const partialAllowed = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace(
      `            echo "::error::Arbeitsbereich-Browser-Proof ist unvollständig; Web- und App-Modus-Harness müssen gemeinsam vorliegen."
            exit 1`,
      '            echo "workspace_browser=false" >> "$GITHUB_OUTPUT"',
    ),
  };
  assert.match(
    validateSourceConfidentiality(partialAllowed, assetSelector).join("\n"),
    /partial Workspace harness availability must fail closed/,
  );

  const publicTabs = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace("workspace-tabs-proof", "workspace-tabs-public"),
  };
  assert.match(
    validateSourceConfidentiality(publicTabs, assetSelector).join("\n"),
    /workspace-tabs-proof must suppress private output|Workspace tab proof must run confidentially/,
  );

  const publicAppPlugins = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace("workspace-app-plugins-proof", "workspace-app-plugins-public"),
  };
  assert.match(
    validateSourceConfidentiality(publicAppPlugins, assetSelector).join("\n"),
    /workspace-app-plugins-proof must suppress private output|Workspace app-plugin proof must run confidentially/,
  );

  const rawUpload = {
    ...fixtures,
    "pr-check.yml": `${fixtures["pr-check.yml"]}\n      - uses: actions/upload-artifact@${"a".repeat(40)}\n        with:\n          path: \${{ runner.temp }}/scai-workspace-tabs/\n`,
  };
  assert.match(
    validateSourceConfidentiality(rawUpload, assetSelector).join("\n"),
    /raw Workspace proof output must not be uploaded/,
  );
});

test("Workspace and Call diagnostics require the supplied key and the three exact encrypted envelopes", () => {
  for (const [stepId, diagnosticName, expected] of [
    ["workspace_tabs_proof", "scai-workspace-tabs-diagnostic.json", /Workspace tab diagnostics/],
    ["workspace_app_plugins_proof", "scai-workspace-app-plugins-diagnostic.json", /Workspace app-plugin diagnostics/],
    ["subunit_call_proof", "scai-subunit-call-diagnostic.json", /Subunit Call diagnostics/],
  ]) {
    const missingKeyGuard = {
      ...fixtures,
      "pr-check.yml": fixtures["pr-check.yml"].replace(
        `if: failure() && steps.${stepId}.outcome == 'failure' && inputs.diagnostic_public_key_base64 != ''`,
        `if: failure() && steps.${stepId}.outcome == 'failure'`,
      ),
    };
    assert.match(
      validateSourceConfidentiality(missingKeyGuard, assetSelector).join("\n"),
      expected,
    );

    const plaintextUpload = {
      ...fixtures,
      "pr-check.yml": fixtures["pr-check.yml"].replace(
        `path: \${{ runner.temp }}/${diagnosticName}`,
        `path: src/private-${diagnosticName.replace("-diagnostic.json", ".log")}`,
      ),
    };
    assert.match(
      validateSourceConfidentiality(plaintextUpload, assetSelector).join("\n"),
      expected,
    );

    const broadUpload = {
      ...fixtures,
      "pr-check.yml": fixtures["pr-check.yml"].replace(
        `path: \${{ runner.temp }}/${diagnosticName}`,
        `path: \${{ runner.temp }}/${diagnosticName.replace("-diagnostic.json", "/")}`,
      ),
    };
    assert.match(
      validateSourceConfidentiality(broadUpload, assetSelector).join("\n"),
      /raw Workspace proof output|Workspace .* diagnostics|Subunit Call diagnostics/,
    );
  }
});

test("Subunit Call proof remains ref-bound, confidential, and runnable after an earlier failure", () => {
  const scriptOnlyDetection = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace(
      "[ ! -f src/call/CallSessionHost.tsx ] || subunit_call_host=true",
      "subunit_call_host=true",
    ),
  };
  assert.match(
    validateSourceConfidentiality(scriptOnlyDetection, assetSelector).join("\n"),
    /Subunit Call proof detection must retain/,
  );

  const partialAllowed = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace(
      `            echo "::error::Subunit-Call-Proof ist unvollständig; Call-Host und Proof-Harness müssen gemeinsam vorliegen."
            exit 1`,
      '            echo "subunit_call=false" >> "$GITHUB_OUTPUT"',
    ),
  };
  assert.match(
    validateSourceConfidentiality(partialAllowed, assetSelector).join("\n"),
    /partial Subunit Call capability availability must fail closed/,
  );

  const publicProof = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace("subunit-call-proof", "subunit-call-public"),
  };
  assert.match(
    validateSourceConfidentiality(publicProof, assetSelector).join("\n"),
    /subunit-call-proof must suppress private output|Subunit Call proof must run confidentially/,
  );

  const priorFailureSkipsProof = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace(
      "if: always() && steps.source_proofs.outputs.subunit_call == 'true'",
      "if: steps.source_proofs.outputs.subunit_call == 'true'",
    ),
  };
  assert.match(
    validateSourceConfidentiality(priorFailureSkipsProof, assetSelector).join("\n"),
    /Subunit Call proof must run confidentially/,
  );

  for (const rawPath of [
    "~/.cache/u1-shots/subunit-call/",
    "~/.cache/u1-shots/subunit-call/report.json",
    '"/home/runner/.cache/u1-shots/subunit-call"',
    "'/home/runner/.cache/u1-shots/subunit-call/**/*.png'",
    "${{ runner.temp }}/subunit-call-report.json",
    "${{ runner.temp }}/call-audio-caller-final.webm",
    "${{ runner.temp }}/call-active-caller-390-light.png",
  ]) {
    const rawCallArtifact = {
      ...fixtures,
      "pr-check.yml": `${fixtures["pr-check.yml"]}\n      - uses: actions/upload-artifact@${"a".repeat(40)}\n        with:\n          path: ${rawPath}\n`,
    };
    assert.match(
      validateSourceConfidentiality(rawCallArtifact, assetSelector).join("\n"),
      /raw Subunit Call screenshots, recordings, reports, and the real proof output directory/,
    );
  }
});

test("Revenue screenshots can upload only after closed sanitization", () => {
  const rawUpload = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace(
      "path: ${{ runner.temp }}/scai-revenue-browser-encrypted-shots.json",
      "path: ${{ runner.temp }}/scai-revenue-source-shots/",
    ),
  };
  const errors = validateSourceConfidentiality(rawUpload, assetSelector).join("\n");
  assert.match(errors, /raw Revenue source proof output must never be uploaded/);
  assert.match(errors, /Revenue proof may upload only its encrypted screenshot envelope/);

  const noSanitizer = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace(
      "steps.revenue_artifacts.outcome == 'success'",
      "steps.offers_revenue_proof.outcome == 'success'",
    ),
  };
  assert.match(
    validateSourceConfidentiality(noSanitizer, assetSelector).join("\n"),
    /may upload only its sanitized fixture screenshot directory/,
  );
});

test("Workgraph harness remains optional, but runs confidentially and sanitizes all output when present", () => {
  const undetected = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace(
      "if [ -f scripts/verify-workgraph-blackbox.mjs ]; then",
      "if false; then",
    ),
  };
  assert.match(validateSourceConfidentiality(undetected, assetSelector).join("\n"), /Workgraph proof must be optional/);

  const publicHarness = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace("workgraph-blackbox-proof", "workgraph-public-proof"),
  };
  assert.match(validateSourceConfidentiality(publicHarness, assetSelector).join("\n"), /workgraph-blackbox-proof must suppress private output/);

  const noWorkgraphSanitizer = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace(
      '--workgraph-only "$HOME/.cache/u1-shots/scai-workgraph-blackbox"',
      '--workgraph-disabled "$HOME/.cache/u1-shots/scai-workgraph-blackbox"',
    ),
  };
  assert.match(validateSourceConfidentiality(noWorkgraphSanitizer, assetSelector).join("\n"), /Revenue and Workgraph screenshots must pass/);

  const uncheckedWorkgraphOnly = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace(
      "steps.source_proofs.outputs.revenue_browser != 'true' && steps.source_proofs.outputs.workgraph_blackbox == 'true' && steps.workgraph_blackbox_proof.outcome == 'success'",
      "steps.source_proofs.outputs.workgraph_blackbox == 'true'",
    ),
  };
  assert.match(validateSourceConfidentiality(uncheckedWorkgraphOnly, assetSelector).join("\n"), /artifact modes must require/);

  const rawUpload = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace(
      "path: ${{ runner.temp }}/scai-revenue-browser-encrypted-shots.json",
      "path: ~/.cache/u1-shots/scai-workgraph-blackbox/",
    ),
  };
  assert.match(validateSourceConfidentiality(rawUpload, assetSelector).join("\n"), /raw Workgraph source proof output/);
});

test("Workforce Inbox proof remains optional, isolated, and confidential", () => {
  const undetected = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace(
      "if [ -f scripts/verify-workforce-inbox.mjs ]; then",
      "if false; then",
    ),
  };
  assert.match(validateSourceConfidentiality(undetected, assetSelector).join("\n"), /Workforce Inbox proof must be optional/);

  const publicHarness = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace(
      'run-confidential.sh" workforce-inbox-proof',
      'run-publicly.sh" workforce-inbox-proof',
    ),
  };
  assert.match(
    validateSourceConfidentiality(publicHarness, assetSelector).join("\n"),
    /workforce-inbox-proof must suppress private output|Workforce Inbox proof must run confidentially/,
  );

  const sourceOutput = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace(
      "SCAI_WORKFORCE_INBOX_PROOF_DIR: ${{ runner.temp }}/scai-workforce-inbox-proof",
      "SCAI_WORKFORCE_INBOX_PROOF_DIR: src/private-workforce-inbox-output",
    ),
  };
  assert.match(
    validateSourceConfidentiality(sourceOutput, assetSelector).join("\n"),
    /Workforce Inbox proof must run confidentially into its isolated fixture directory/,
  );
});

test("Revenue diagnostics cannot upload plaintext or a source-tree path", () => {
  for (const [safePath, unsafePath, expected] of [
    ["${{ runner.temp }}/scai-revenue-billing-diagnostic.json", "src/private-billing.log", /Billing Revenue diagnostics/],
    ["${{ runner.temp }}/scai-revenue-offers-diagnostic.json", "src/private-offers.log", /Offers Revenue diagnostics/],
  ]) {
    const unsafe = {
      ...fixtures,
      "pr-check.yml": fixtures["pr-check.yml"].replace(`path: ${safePath}`, `path: ${unsafePath}`),
    };
    assert.match(validateSourceConfidentiality(unsafe, assetSelector).join("\n"), expected);
  }
});

test("Workgraph diagnostics cannot upload plaintext or a source-tree path", () => {
  const unsafe = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace(
      "path: ${{ runner.temp }}/scai-workgraph-blackbox-diagnostic.json",
      "path: src/private-workgraph.log",
    ),
  };
  assert.match(
    validateSourceConfidentiality(unsafe, assetSelector).join("\n"),
    /Workgraph diagnostics may upload only a one-time-key encrypted envelope/,
  );
});

test("Chat-Dock diagnostics cannot upload plaintext or a source-tree path", () => {
  const unsafe = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace(
      "path: ${{ runner.temp }}/scai-chat-dock-diagnostic.json",
      "path: src/private-chat-dock.log",
    ),
  };
  assert.match(
    validateSourceConfidentiality(unsafe, assetSelector).join("\n"),
    /Chat-Dock diagnostics may upload only a one-time-key encrypted envelope/,
  );
});

test("Windows ARM smoke preserves the clang-cl exception flag", () => {
  const unsafe = {
    ...fixtures,
    "windows-arm-smoke.yml": fixtures["windows-arm-smoke.yml"].replace(
      "MSYS2_ENV_CONV_EXCL=CXXFLAGS_aarch64_pc_windows_msvc",
      "MSYS2_ENV_CONV_EXCL=",
    ),
  };
  assert.match(validateSourceConfidentiality(unsafe, assetSelector).join("\n"), /must not rewrite the clang-cl exception flag/);
});

test("Windows ARM smoke keeps the release lane's OpenSSL environment", () => {
  const unsafe = {
    ...fixtures,
    "windows-arm-smoke.yml": fixtures["windows-arm-smoke.yml"].replace(
      "OPENSSL_TRIPLET: arm64-windows-static-md",
      "OPENSSL_TRIPLET:",
    ),
  };
  assert.match(validateSourceConfidentiality(unsafe, assetSelector).join("\n"), /same vcpkg OpenSSL environment/);
});

test("the native keyring smoke stays outside Tauri binary targets", () => {
  const unsafe = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace("--example a1_keyring_smoke", "--bin a1_keyring_smoke"),
  };
  const errors = validateSourceConfidentiality(unsafe, assetSelector).join("\n");
  assert.match(errors, /keyring smoke must stay an example in both manifest-derived branches/);
  assert.match(errors, /must not reintroduce a Cargo bin target/);
});

test("the native keyring smoke derives legacy feature use from the pinned manifest", () => {
  const unsafe = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace(
      "if grep -Eq '^[[:space:]]*a1-keyring-smoke[[:space:]]*=' src-tauri/Cargo.toml; then",
      "if false; then",
    ),
  };
  assert.match(
    validateSourceConfidentiality(unsafe, assetSelector).join("\n"),
    /must support old and new pinned manifests without Bash 3\.2 empty-array expansion/,
  );
});

test("the native keyring smoke cannot require the legacy feature unconditionally", () => {
  const unsafe = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace(
      "              --example a1_keyring_smoke",
      "              --features a1-keyring-smoke --example a1_keyring_smoke",
    ),
  };
  const errors = validateSourceConfidentiality(unsafe, assetSelector).join("\n");
  assert.match(errors, /must support old and new pinned manifests without Bash 3\.2 empty-array expansion/);
});

test("the native keyring smoke cannot use an empty feature array under Bash 3.2", () => {
  const unsafe = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace(
      "          if grep -Eq '^[[:space:]]*a1-keyring-smoke[[:space:]]*=' src-tauri/Cargo.toml; then",
      "          keyring_features=()\n          if grep -Eq '^[[:space:]]*a1-keyring-smoke[[:space:]]*=' src-tauri/Cargo.toml; then",
    ),
  };
  assert.match(
    validateSourceConfidentiality(unsafe, assetSelector).join("\n"),
    /must support old and new pinned manifests without Bash 3\.2 empty-array expansion/,
  );
});

test("standalone Trace checks cannot accept a mutable ref", () => {
  const unsafe = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace(
      "trace_ref muss ein unveränderlicher 40-Zeichen-SHA sein.",
      "trace_ref wird als Branch akzeptiert.",
    ),
  };
  assert.match(validateSourceConfidentiality(unsafe, assetSelector).join("\n"), /reject mutable refs/);
});

test("standalone Trace native output cannot bypass the confidential runner", () => {
  const unsafe = {
    ...fixtures,
    "pr-check.yml": fixtures["pr-check.yml"].replace("trace-native-test cargo test", "trace-test-plain cargo test"),
  };
  assert.match(validateSourceConfidentiality(unsafe, assetSelector).join("\n"), /trace-native-test must suppress private output/);
});

test("release packaging cannot skip the product-binary target proof", () => {
  const unsafe = {
    ...fixtures,
    "build-all.yml": fixtures["build-all.yml"].replace(
      'run-confidential.sh" "product-binary-$TARGET"',
      'run-confidential.sh" "unchecked-product-$TARGET"',
    ),
  };
  assert.match(
    validateSourceConfidentiality(unsafe, assetSelector).join("\n"),
    /product-binary metadata must be checked confidentially/,
  );
});

test("the ARM64 release lane cannot drop the triplet the smoke mirrors", () => {
  const unsafe = {
    ...fixtures,
    "build-all.yml": fixtures["build-all.yml"].replace(
      "openssl_triplet: arm64-windows-static-md",
      "openssl_triplet: arm64-windows",
    ),
  };
  assert.match(validateSourceConfidentiality(unsafe, assetSelector).join("\n"), /triplet the smoke mirrors/);
});

for (const label of ["auth-install", "auth-db-fixture", "auth-tests", "auth-build", "auth-deploy-gate"]) {
  test(`Auth ${label} cannot expose private output`, () => {
    const unsafe = { ...fixtures, "auth-pr-check.yml": fixtures["auth-pr-check.yml"].replace(`run-confidential.sh" ${label}`, `plain.sh" ${label}`) };
    assert.match(validateSourceConfidentiality(unsafe, assetSelector).join("\n"), /must suppress private output/);
  });
}
test("Auth diagnostic artifact cannot point at private source", () => {
  const unsafe = { ...fixtures, "auth-pr-check.yml": fixtures["auth-pr-check.yml"].replace("path: ${{ runner.temp }}/auth-diagnostic.json", "path: private/subunit-auth") };
  assert.match(validateSourceConfidentiality(unsafe, assetSelector).join("\n"), /encrypted diagnostic envelope/);
});

test("Auth PostgreSQL image cannot use a mutable tag", () => {
  const unsafe = { ...fixtures, "auth-pr-check.yml": fixtures["auth-pr-check.yml"].replace(/postgres@sha256:[0-9a-f]{64}/, "postgres:16") };
  assert.match(validateSourceConfidentiality(unsafe, assetSelector).join("\n"), /immutable digest/);
});

test("Auth full suite cannot become a partial test selection", () => {
  const unsafe = { ...fixtures, "auth-pr-check.yml": fixtures["auth-pr-check.yml"].replace("bash scripts/ci/run-proof-suite.sh", "bun test test/one.test.ts") };
  assert.match(validateSourceConfidentiality(unsafe, assetSelector).join("\n"), /partial test commands/);
});
test("Auth discovery keys require unconditional cleanup", () => {
  const workflow = fixtures["auth-pr-check.yml"].replace('"$RUNNER_TEMP/auth-cutover-discovery-public.pem"\n', '\n');
  const unsafe = { ...fixtures, "auth-pr-check.yml": workflow.replace('"$RUNNER_TEMP/auth-cutover-discovery-private.pem" "$RUNNER_TEMP/auth-cutover-discovery-public.pem"','') };
  assert.match(validateSourceConfidentiality(unsafe, assetSelector).join("\n"), /unconditional cleanup/);
});

test('restored mail and capacity contracts cannot silently skip or expose private output',()=>{
 const original=fixtures['pr-check.yml'];
 for(const [before,after] of [
  ['detect-recovered-source-proofs.sh','removed-pair-check.sh'],
  ["if: always() && steps.source_proofs.outputs.email_full_peek == 'true'",'if: false'],
  ["if: always() && steps.source_proofs.outputs.backoffice_capacity == 'true'",'if: false'],
  ['run-confidential.sh" email-full-peek-proof','echo" email-full-peek-proof'],
  ['run-confidential.sh" backoffice-capacity-proof','echo" backoffice-capacity-proof'],
  ["if: failure() && steps.email_full_peek_proof.outcome == 'failure' && inputs.diagnostic_public_key_base64 != ''",'if: always()'],
  ['path: ${{ runner.temp }}/scai-backoffice-capacity-diagnostic.json','path: src/'],
 ]){
  assert.ok(original.includes(before),before);
  assert.ok(validateSourceConfidentiality({...fixtures,'pr-check.yml':original.replace(before,after)},assetSelector).length>0,before);
 }
});

for (const key of ["email_full_peek", "backoffice_capacity", "agents_os", "workforce_coordination", "migration_host", "native_usage_core"]) {
  for (const [label, mutate] of [
    ["ignored failure", source => source.replace(`        id: ${key}_proof`, `        id: ${key}_proof\n        continue-on-error: true`)],
    ["quoted ignored failure", source => source.replace(`        id: ${key}_proof`, `        id: ${key}_proof\n        "continue-on-error": true`)],
    ["comment decoy", source => source.replace(`        if: always() && steps.source_proofs.outputs.${key} == 'true'`, `        if: false\n        # if: always() && steps.source_proofs.outputs.${key} == 'true'`)],
    ["duplicate step", source => source + `\n      - name: Duplicate proof\n        id: ${key}_proof\n        run: true\n`],
    ["commented wrapper", source => source.replace(`        run: bash "$GITHUB_WORKSPACE/gate/scripts/run-confidential.sh" ${key.replaceAll("_", "-")}-proof`, `        run: echo skipped\n        # run: bash "$GITHUB_WORKSPACE/gate/scripts/run-confidential.sh" ${key.replaceAll("_", "-")}-proof`)],
    ["upload condition decoy", source => source.replace(`        if: failure() && steps.${key}_proof.outcome == 'failure' && inputs.diagnostic_public_key_base64 != ''`, `        if: always()\n        # if: failure() && steps.${key}_proof.outcome == 'failure' && inputs.diagnostic_public_key_base64 != ''`)],
  ]) {
    test(`recovered ${key} proof rejects ${label}`, () => {
      const changed = mutate(fixtures["pr-check.yml"]);
      assert.notEqual(changed, fixtures["pr-check.yml"]);
      assert.ok(validateSourceConfidentiality({ ...fixtures, "pr-check.yml": changed }, assetSelector).some(error => error.includes(key.replaceAll("_", "-"))));
    });
  }
}

for (const [key,label] of [['agents_os','agents-os'],['workforce_coordination','workforce-coordination'],['migration_host','migration-host']]) {
 const condition=`if: always() && steps.source_proofs.outputs.${key} == 'true' && (steps.${key}_proof.outcome == 'success' || steps.${key}_proof.outcome == 'failure') && steps.${key}_proof.outputs.encrypted_visual_receipt == 'true' && inputs.diagnostic_public_key_base64 != ''`;
 for (const [name,before,after] of [
  ['unconditional upload',condition,'if: always()'],
  ['skipped proof upload',condition,`if: always() && inputs.diagnostic_public_key_base64 != ''`],
  ['raw path',`path: \${{ runner.temp }}/scai-${label}-encrypted-proof.json`,'path: src/'],
  ['long retention',`name: scai-${label}-encrypted-proof-\${{ github.run_id }}\n          path: \${{ runner.temp }}/scai-${label}-encrypted-proof.json\n          if-no-files-found: error\n          retention-days: 1`,`name: scai-${label}-encrypted-proof-\${{ github.run_id }}\n          path: \${{ runner.temp }}/scai-${label}-encrypted-proof.json\n          if-no-files-found: error\n          retention-days: 90`],
  ['ignored upload failure',`- name: Verschluesselte ${label} Visualbelege bereitstellen`,`- name: Verschluesselte ${label} Visualbelege bereitstellen\n        continue-on-error: true`],
 ]) test(`${label} visual receipt rejects ${name}`,()=>{
  const original=fixtures['pr-check.yml'];assert.ok(original.includes(before));const changed=original.replace(before,after);assert.ok(validateSourceConfidentiality({...fixtures,'pr-check.yml':changed},assetSelector).some(e=>e.includes(`${label} visual proof`)));
 });
}
for (const label of ['agents-os','workforce-coordination','migration-host']) test(`${label} rejects duplicate visual envelope upload under another name`,()=>{
 const changed=fixtures['pr-check.yml']+`\n      - name: Extra upload\n        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02\n        with:\n          path: \${{ runner.temp }}/scai-${label}-encrypted-proof.json\n`;
 assert.ok(validateSourceConfidentiality({...fixtures,'pr-check.yml':changed},assetSelector).some(e=>e.includes(`${label} visual proof`)));
});

for(const [label,before,after] of [
 ['failure ignored','id: frontend_build','id: frontend_build\n        continue-on-error: true'],
 ['proof skipped','id: frontend_build','id: frontend_build\n        if: false'],
 ['wrapper skipped','run-confidential.sh" frontend-build','echo" frontend-build'],
 ['raw upload','path: ${{ runner.temp }}/scai-frontend-build-diagnostic.json','path: src/'],
 ['success upload',"if: failure() && steps.frontend_build.outcome == 'failure' && inputs.diagnostic_public_key_base64 != ''",'if: always()'],
 ['key missing',"format('{0}/scai-frontend-build-diagnostic.json', runner.temp)","format('{0}/wrong-diagnostic.json', runner.temp)"],
 ['upload failure ignored','- name: Verschlüsselte Frontend-Build-Fehlerdiagnostik bereitstellen','- name: Verschlüsselte Frontend-Build-Fehlerdiagnostik bereitstellen\n        continue-on-error: true'],
])test(`frontend build diagnostic rejects ${label}`,()=>{
 const original=fixtures['pr-check.yml'];assert.ok(original.includes(before));assert.ok(validateSourceConfidentiality({...fixtures,'pr-check.yml':original.replace(before,after)},assetSelector).some(e=>e.includes('Frontend build diagnostics')));
});

for(const [label,before,after] of [
 ['failure ignored','id: cargo_test','id: cargo_test\n        continue-on-error: true'],
 ['proof skipped','id: cargo_test','id: cargo_test\n        if: false'],
 ['wrapper skipped','run-confidential.sh" cargo-test','echo" cargo-test'],
 ['raw upload','path: ${{ runner.temp }}/scai-cargo-test-diagnostic.json','path: src/'],
 ['success upload',"if: failure() && steps.cargo_test.outcome == 'failure' && inputs.diagnostic_public_key_base64 != ''",'if: always()'],
 ['key missing',"format('{0}/scai-cargo-test-diagnostic.json', runner.temp)","format('{0}/wrong-diagnostic.json', runner.temp)"],
 ['upload failure ignored','- name: Verschlüsselte Cargo-Test-Fehlerdiagnostik bereitstellen','- name: Verschlüsselte Cargo-Test-Fehlerdiagnostik bereitstellen\n        continue-on-error: true'],
])test(`cargo test diagnostic rejects ${label}`,()=>{
 const original=fixtures['pr-check.yml'];assert.ok(original.includes(before));assert.ok(validateSourceConfidentiality({...fixtures,'pr-check.yml':original.replace(before,after)},assetSelector).some(e=>e.includes('Cargo test diagnostics')));
});

for(const [label,transform] of [
 ["missing recipient",s=>s.replace('SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64: ${{ inputs.diagnostic_public_key_base64 }}',"SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64: ''")],
 ["long retention",s=>s.replace('retention-days: 1','retention-days: 2')],
 ["filtered command",s=>s.replace('--lib --features local-meet','--lib --features local-meet native_usage')],
 ["duplicate upload",s=>s+'\n'+s.slice(s.indexOf('      - name: Verschlüsselte Cargo-Test-Fehlerdiagnostik bereitstellen'))],
])test(`cargo test diagnostic rejects ${label}`,()=>{
 const original=fixtures['pr-check.yml'];const start=original.indexOf('      - name: cargo test (Sidecar-Trust-Modell');const end=original.indexOf('      - name: Private Trace-Credentials entfernen',start);const block=original.slice(start,end);const altered=transform(block);assert.notEqual(altered,block);const changed=original.slice(0,start)+altered+original.slice(end);assert.ok(validateSourceConfidentiality({...fixtures,'pr-check.yml':changed},assetSelector).some(e=>e.includes('Cargo test diagnostics')));
});
for(const [name,mutate] of [
 ['skip mandatory Radar',s=>s.replace("if: always() && steps.source_proofs.outputs.radar == 'true'","if: false")],
 ['allow failed Radar',s=>s.replace('id: radar_proof','id: radar_proof\n        continue-on-error: true')],
 ['raw Radar artifact',s=>s.replace('path: ${{ runner.temp }}/scai-radar-encrypted-proof.json','path: src/**')],
 ['extend Radar retention',s=>s.replace(/(name: scai-radar-encrypted-proof-[\s\S]*?retention-days: )1/,'$27')],
])test(name,()=>{
 const unsafe={...fixtures,'pr-check.yml':mutate(fixtures['pr-check.yml'])};assert.ok(validateSourceConfidentiality(unsafe,assetSelector).some(e=>e.includes('radar')));
});
for(const field of ['SOURCE_SHA','REQUEST_ID'])test(`Radar rejects absent ${field} binding`,()=>{
 const value=field==='SOURCE_SHA'?'source_sha':'request_id';
 const block=fixtures['pr-check.yml'];const start=block.indexOf('      - name: Restored radar contract beweisen');
 const prefix=block.slice(0,start),rest=block.slice(start).replace(`          ${field}: \${{ needs.preflight.outputs.${value} }}\n`,'');
 assert.ok(validateSourceConfidentiality({...fixtures,'pr-check.yml':prefix+rest},assetSelector).some(e=>e.includes('radar')));
});

// Mutationen an jeder vertraulichen Grenze müssen die geschlossene Sonar-Policy brechen.
for (const [name, mutate] of [
  ['automatischer Trigger', s => s.replace('  workflow_dispatch:', '  push:')],
  ['schreibende CI-Permissions', s => s.replace('contents: read', 'contents: write')],
  ['parallele Release-Gruppe', s => s.replace('group: sonar-release', 'group: sonar-${{ inputs.tag }}')],
  ['Build ohne Preflight', s => s.replace('needs: preflight', 'needs: []')],
  ['Publish trotz roter Matrix', s => s.replace('needs: [preflight, build]', 'needs: preflight')],
  ['Quellcode-Upload', s => s.replace('path: ${{ steps.delivery.outputs.paths }}', 'path: private/')],
  ['Sidecar-Upload', s => s.replace('path: ${{ steps.delivery.outputs.paths }}', 'path: private/sonar-tauri/src-tauri/binaries/')],
  ['Klartext-Diagnose', s => s.replace('path: ${{ steps.sealed_diagnostic.outputs.path }}', 'path: private/build.log')],
  ['Screenshot-Upload', s => s.replace('path: ${{ steps.sealed_diagnostic.outputs.path }}', 'path: private/screenshot.png')],
  ['Diagnose-Glob außerhalb RUNNER_TEMP', s => s.replace('path: ${{ steps.sealed_diagnostic.outputs.path }}', 'path: ${{ github.workspace }}/sonar-diagnostic*.json')],
  ['Diagnose-Glob mit Traversal', s => s.replace('path: ${{ steps.sealed_diagnostic.outputs.path }}', 'path: ${{ runner.temp }}/../sonar-diagnostic*.json')],
  ['Diagnose-Glob für Rohlogs', s => s.replace('path: ${{ steps.sealed_diagnostic.outputs.path }}', 'path: ${{ runner.temp }}/sonar-diagnostic*')],
  ['rekursiver Diagnose-Glob', s => s.replace('path: ${{ steps.sealed_diagnostic.outputs.path }}', 'path: ${{ runner.temp }}/**/*.json')],
  ['Diagnose ohne verschachtelte Hüllen', s => s.replace('path: ${{ steps.sealed_diagnostic.outputs.path }}', 'path: ${{ runner.temp }}/sonar-diagnostic.json')],
  ['lange Retention', s => s.replace('retention-days: 1', 'retention-days: 7')],
  ['öffentlicher Build', s => s.replace('bash gate/scripts/run-confidential.sh sonar-tauri ', '')],
  ['öffentliche Installation', s => s.replace('bash gate/scripts/run-confidential.sh sonar-frontend ', '')],
  ['fehlender Deploy-Key', s => s.replace('secrets.SONAR_SOURCE_DEPLOY_KEY', 'secrets.GITHUB_TOKEN')],
  ['fremdes App-Token-Ziel', s => s.replace('repositories: sonar-releases', 'repositories: sonar-tauri')],
  ['unpinned Action', s => s.replace('create-github-app-token@fee1f7d63c2ff003460e3d139729b119787bc349', 'create-github-app-token@v2')],
  ['kein Tag-Drift-Guard', s => s.replace('"$SOURCE_SHA" "$COMPONENT_TAG"', '"$SOURCE_SHA"')],
  ['mutable Source', s => s.replace('needs.preflight.outputs.source_sha', 'inputs.source_sha')],
  ['private Build-Caches', s => s + '\n      - uses: actions/cache@' + 'a'.repeat(40) + '\n'],
  ['Clobber', s => s.replace('publish "$RUNNER_TEMP/sonar-installers"', 'publish "$RUNNER_TEMP/sonar-installers" --clobber')],
  ['tauri-action-Release', s => s + '\n      - uses: tauri-apps/tauri-action@' + 'a'.repeat(40) + '\n'],
  ['set-x', s => s.replace('run: bash gate/scripts/run-confidential.sh sonar-tauri', 'run: set -x; bash gate/scripts/run-confidential.sh sonar-tauri')],
  ['Build-Fehler ignorieren', s => s.replace('name: Tauri-Bundles und Updater-Signaturen bauen', 'name: Tauri-Bundles und Updater-Signaturen bauen\n        continue-on-error: true')],
  ['Upload ungeprüfter Dateien', s => s.replace('run-confidential.sh sonar-collect', 'run-confidential.sh ungeprüft')],
  ['Upload ohne Inventarprüfung', s => s.replace('id: delivery', 'id: unchecked_delivery')],
  ['Räumschranke übersprungen', s => s.replace('if: always()\n        shell: bash\n        run: bash gate/scripts/checkout-private-source.sh --cleanup-credentials', 'if: false\n        shell: bash\n        run: bash gate/scripts/checkout-private-source.sh --cleanup-credentials')],
  ['Räumschranke ignoriert Fehler', s => s.replace('run: bash gate/scripts/checkout-private-source.sh --cleanup-credentials', 'run: bash gate/scripts/checkout-private-source.sh --cleanup-credentials || true')],
  ['Diagnose ohne erneute Verschlüsselung', s => s.replace('run: node gate/scripts/sonar-release.mjs seal-diagnostics', 'run: true')],
  ['Upload ursprünglicher Diagnose-Dateien', s => s.replace('path: ${{ steps.sealed_diagnostic.outputs.path }}', 'path: ${{ runner.temp }}/sonar-diagnostic*.json')],
  ['fehlende Signaturprüfung', s => s.replace('run-confidential.sh sonar-manifest', 'run-confidential.sh ungeprüft')],
  ['Diagnose ohne Einmalschlüssel', s => s.replace("if: failure() && inputs.diagnostic_public_key_base64 != ''", 'if: always()')],
  ['zusätzlicher YAML-Bypass', s => s.replace('jobs:', 'env:\n  ACTIONS_STEP_DEBUG: true\njobs:')],
]) test(`Sonar-Policy sperrt ${name}`, () => {
  const original = fixtures['sonar-build.yml'];
  const changed = mutate(original);
  assert.notEqual(changed, original);
  assert.ok(validateSourceConfidentiality({ ...fixtures, 'sonar-build.yml': changed }, assetSelector).some(e => e.startsWith('sonar-build.yml:')));
});
test('Sonar-Policy verlangt den Workflow auch bei fehlendem Inventareintrag', () => {
  const { 'sonar-build.yml': omitted, ...rest } = fixtures;
  assert.ok(omitted);
  assert.ok(validateSourceConfidentiality(rest, assetSelector).some(e => e.startsWith('sonar-build.yml:')));
});

test('Sonar-Policy bindet auch die ausgeführten Helfer an den geprüften Vertrag', () => {
  const helpers = Object.fromEntries(['sonar-build.sh', 'sonar-minisign.sh', 'sonar-release.mjs', 'checkout-private-source.sh', 'encrypt-confidential-log.mjs'].map(name => [name, readFileSync(join(ROOT, 'scripts', name), 'utf8')]));
  assert.deepEqual(validateSonarHelpers(helpers), []);
  for (const name of Object.keys(helpers)) {
    assert.ok(validateSonarHelpers({ ...helpers, [name]: helpers[name] + '\n# ungeprüfte Änderung\n' }).some(e => e.includes(name)));
    assert.ok(validateSonarHelpers({ ...helpers, [name]: undefined }).some(e => e.includes(name)));
  }
  for (const [name, before, after] of [
    ['sonar-build.sh', 'bun install --frozen-lockfile', 'bun install'],
    ['sonar-build.sh', "bun_target=bun-windows-x64", "bun_target=bun-windows-arm64"],
    ['sonar-minisign.sh', 'sha256sum -c -', 'true'],
    ['sonar-release.mjs', "checkRemote(releaseTag);", "// Vorflug übersprungen"],
    ['sonar-release.mjs', "['release', 'upload', releaseTag", "['release', 'upload', '--clobber', releaseTag"],
    ['sonar-release.mjs', "verify(join(directory, name), Buffer.from(signature, 'base64'));", "// Signaturprüfung übersprungen"],
    ['checkout-private-source.sh', 'GlobalKnownHostsFile=/dev/null', 'GlobalKnownHostsFile=~/.ssh/known_hosts'],
    ['checkout-private-source.sh', 'UserKnownHostsFile=$known_hosts', 'UserKnownHostsFile=$HOME/.ssh/known_hosts'],
    ['checkout-private-source.sh', 'umask 077', 'umask 022'],
    ['checkout-private-source.sh', 'mktemp -d "$credential_root/scai-checkout-credentials.XXXXXX"', 'echo "$credential_root/fixed-credentials"'],
    ['checkout-private-source.sh', 'unset SOURCE_DEPLOY_KEY\n', ': # credential retained\n'],
    ['sonar-build.sh', 'node "$gate_root/sonar-release.mjs" frontend-build "$source_root" "$target"', 'bun run tauri build'],
    ['sonar-release.mjs', 'const before = verifyFrontend(source);', 'const before = {};'],
    ['sonar-release.mjs', 'const after = verifyFrontend(source);', 'const after = before;'],
    ['sonar-release.mjs', 'before.binding !== after.binding', 'false'],
    ['sonar-release.mjs', 'before.hash !== after.hash', 'false'],
    ['sonar-release.mjs', 'before.configHash !== after.configHash', 'false'],
    ['sonar-release.mjs', 'JSON.stringify(records)', 'JSON.stringify([])'],
    ['sonar-release.mjs', 'JSON.stringify([configRecord])', 'JSON.stringify([])'],
    ['sonar-release.mjs', "frontendExtensions.has(extname(name).toLowerCase())", 'true'],
    ['sonar-release.mjs', 'if (confidentialMarker(data))', 'if (false)'],
    ['sonar-release.mjs', 'if (archiveHeader(data))', 'if (false)'],
    ['sonar-release.mjs', 'before.nlink !== 1n', 'false'],
    ['sonar-release.mjs', 'entries > FRONTEND_LIMITS.entries', 'false'],
    ['sonar-release.mjs', 'bytes > FRONTEND_LIMITS.totalBytes', 'false'],
    ['sonar-release.mjs', 'process.env.TAURI_CONFIG !== undefined', 'false'],
    ['sonar-release.mjs', '"beforeBuildCommand":"","beforeBundleCommand":"","frontendDist":"../dist"', '"beforeBuildCommand":""'],
  ]) {
    assert.ok(helpers[name].includes(before));
    assert.ok(validateSonarHelpers({ ...helpers, [name]: helpers[name].replace(before, after) }).some(e => e.includes(name)));
  }
});

test('Atlas diagnostics remain encrypted and bound to the exact failed suite',()=>{
 for(const [label,mutate] of [
  ['raw source upload',s=>s.replace('path: ${{ runner.temp }}/atlas-api-diagnostic.json','path: private/atlas/**')],
  ['unconditional upload',s=>s.replace("if: failure() && steps.api_tests.outcome == 'failure' && inputs.diagnostic_public_key_base64 != ''",'if: always()')],
  ['recipient removed',s=>s.replace('SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64: ${{ inputs.diagnostic_public_key_base64 }}','SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64: ""')],
  ['recipient moved outside test step',s=>s.replace('id: api_tests','id: another_step')],
  ['retention expanded',s=>s.replace('retention-days: 1','retention-days: 90')],
  ['missing envelope ignored',s=>s.replace('if-no-files-found: error','if-no-files-found: ignore')],
  ['suite filter',s=>s.replace('atlas-api-tests bun test --isolate','atlas-api-tests bun test --isolate --test-name-pattern docs')],
 ]){
  const changed={...fixtures,'atlas-pr-check.yml':mutate(fixtures['atlas-pr-check.yml'])};assert.notEqual(validateSourceConfidentiality(changed,assetSelector).length,0,label);
 }
});
