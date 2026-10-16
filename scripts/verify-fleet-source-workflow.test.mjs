import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { validateFleetSourceWorkflow } from "./verify-fleet-source-workflow.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const workflow = readFileSync(join(ROOT, ".github/workflows/fleet-source-check.yml"), "utf8");
const helper = readFileSync(join(ROOT, "scripts/checkout-private-source.sh"), "utf8");

test("current public Fleet source workflow fails closed", () => {
  assert.deepEqual(validateFleetSourceWorkflow(workflow, helper), []);
});

test("automatic or fork-controlled triggers are rejected", () => {
  const unsafe = workflow.replace("  workflow_dispatch:", "  pull_request:\n  workflow_dispatch:");
  assert.match(validateFleetSourceWorkflow(unsafe, helper).join("\n"), /automatic or fork trigger/);
});

test("mutable actions are rejected", () => {
  const unsafe = workflow.replace(/oven-sh\/setup-bun@[0-9a-f]{40}/, "oven-sh/setup-bun@v2");
  assert.match(validateFleetSourceWorkflow(unsafe, helper).join("\n"), /action reference must be immutable/);
});

test("public caches and artifacts are rejected", () => {
  const cached = `${workflow}\n      - uses: actions/cache@${"a".repeat(40)}\n`;
  assert.match(validateFleetSourceWorkflow(cached, helper).join("\n"), /must never enter a public Actions cache/);
  const uploaded = `${workflow}\n      - uses: actions/upload-artifact@${"b".repeat(40)}\n`;
  assert.match(validateFleetSourceWorkflow(uploaded, helper).join("\n"), /must not upload public artifacts/);
});

test("one shared deploy key cannot replace repository-specific keys", () => {
  const unsafe = workflow.replaceAll("ATLAS_SOURCE_DEPLOY_KEY", "U1_CHAT_SOURCE_DEPLOY_KEY");
  assert.match(validateFleetSourceWorkflow(unsafe, helper).join("\n"), /distinct secret/);
});

test("private test output cannot bypass the confidential runner", () => {
  const unsafe = workflow.replace('run-confidential.sh" echo-tests ', 'run-confidential-NOT-used.sh" echo-tests ');
  assert.match(validateFleetSourceWorkflow(unsafe, helper).join("\n"), /echo-tests: private output is not confidential/);
});

test("new raw steps or actions cannot run while private source is present", () => {
  const rawStep = workflow.replace(
    '      - name: Temporären privaten Checkout entfernen\n        if: always()\n        shell: bash\n        run: rm -rf -- "$GITHUB_WORKSPACE/private/atlas"',
    '      - name: Unsicherer Raw-Step\n        run: sed -n \'1,20p\' private/atlas/secret.ts\n\n      - name: Temporären privaten Checkout entfernen\n        if: always()\n        shell: bash\n        run: rm -rf -- "$GITHUB_WORKSPACE/private/atlas"',
  );
  assert.match(validateFleetSourceWorkflow(rawStep, helper).join("\n"), /every command while private source exists/);

  const postCheckoutAction = workflow.replace(
    '      - name: Temporären privaten Checkout entfernen\n        if: always()\n        shell: bash\n        run: rm -rf -- "$GITHUB_WORKSPACE/private/echo"',
    `      - uses: attacker/action@${"c".repeat(40)}\n\n      - name: Temporären privaten Checkout entfernen\n        if: always()\n        shell: bash\n        run: rm -rf -- "$GITHUB_WORKSPACE/private/echo"`,
  );
  assert.match(validateFleetSourceWorkflow(postCheckoutAction, helper).join("\n"), /no action may run while private source is present/);
});

test("mutable checkout or missing credential cleanup is rejected", () => {
  const fixtureHead = helper.replace('checkout --detach "$source_sha"', 'checkout --detach FETCH_HEAD');
  assert.notEqual(fixtureHead, helper);
  assert.match(validateFleetSourceWorkflow(workflow, fixtureHead).join("\n"), /detach at the exact requested SHA/);
  const mutable = helper.replace('fetch --depth 1 origin "$source_sha"', 'fetch --depth 1 origin main');
  assert.match(validateFleetSourceWorkflow(workflow, mutable).join("\n"), /exact requested SHA/);
  const dirty = helper.replace("trap 'exit 143' TERM", "# TERM ignored");
  assert.match(validateFleetSourceWorkflow(workflow, dirty).join("\n"), /clean credentials on every exit/);
});

for (const [name, before, after, message] of [
  ['standard host trust', 'GlobalKnownHostsFile=/dev/null', 'GlobalKnownHostsFile=~/.ssh/known_hosts', /isolate the host pin/],
  ['public key permissions', 'umask 077', 'umask 022', /allocate private credentials/],
  ['predictable key path', 'mktemp -d "$credential_root/scai-checkout-credentials.XXXXXX"', 'echo "$credential_root/fixed-key"', /allocate private credentials/],
]) test(`Fleet checkout rejects ${name}`, () => {
  const unsafe = helper.replace(before, after);
  assert.notEqual(unsafe, helper);
  assert.match(validateFleetSourceWorkflow(workflow, unsafe).join('\n'), message);
});

test("host-key drift and retained private checkouts are rejected", () => {
  const unpinnedHost = helper.replace("SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU", "SHA256:unpinned");
  assert.match(validateFleetSourceWorkflow(workflow, unpinnedHost).join("\n"), /pin GitHub's ED25519/);
  const retainedSource = workflow.replace('rm -rf -- "$GITHUB_WORKSPACE/private/atlas"', 'echo retained-atlas-source');
  assert.match(validateFleetSourceWorkflow(retainedSource, helper).join("\n"), /ephemeral private checkout cleanup/);
});

test("mutable Atlas service images are rejected", () => {
  const mutable = workflow.replace(/pgvector\/pgvector@sha256:[0-9a-f]{64}/, "pgvector/pgvector:pg15");
  assert.match(validateFleetSourceWorkflow(mutable, helper).join("\n"), /service image must be digest-pinned/);
});
