#!/usr/bin/env node
import { readFileSync } from "node:fs";

const workflow = readFileSync(new URL("../.github/workflows/echo-pr-check.yml", import.meta.url), "utf8");

const checks = [
  ["nur manueller Trigger", /workflow_dispatch:/u.test(workflow) && !/pull_request:|\npush:/u.test(workflow)],
  ["vollstaendiger SHA ist Pflicht", /\^\[0-9a-f\]\{40\}\$/u.test(workflow)],
  ["nur Leserechte", /permissions:\s*\n\s*contents: read/u.test(workflow)],
  ["Echo-Key ist repo-spezifisch", /secrets\.ECHO_SOURCE_DEPLOY_KEY/u.test(workflow)],
  ["Checkout nutzt die feste Allowlist", /checkout-private-source\.sh echo git@github\.com:Subunit-UG\/echo-server\.git/u.test(workflow)],
  ["Checkout ist SHA-gebunden", /checkout-private-source\.sh echo[^\n]+"\$SOURCE_SHA"/u.test(workflow)],
  ["Third-Party-Actions sind immutable gepinnt", !/uses:\s+[^\s@]+@(?![0-9a-f]{40}(?:\s|$))/u.test(workflow)],
  ["private Ausgaben laufen confidential", (workflow.match(/run-confidential\.sh/g) || []).length >= 5],
  ["vollstaendige Testsuite ist aktiv", /unittest discover -s server\/tests -p 'test_\*\.py' -v/u.test(workflow)],
  ["rote Baseline bleibt fail-closed", /echo-latency-stop-ship/u.test(workflow) && /test_known_30_minute_aggregate_is_stop_ship_and_incomplete/u.test(workflow)],
  ["SQLite-Store ist ab Einfuehrungscommit im Runtime-Image", /if \[ -f server\/meeting_state_store\.py \]; then[\s\S]*meeting_state_store[\s\S]*meeting-state-backup\.py/u.test(workflow)],
  ["privater Checkout wird immer entfernt", /if: always\(\)[\s\S]*rm -rf -- "\$GITHUB_WORKSPACE\/private\/echo"/u.test(workflow)],
  ["keine oeffentlichen Artefakte", !/uses:\s+actions\/upload-artifact@|\bgh\s+release\b/u.test(workflow)],
];

let failed = 0;
for (const [label, ok] of checks) {
  if (ok) console.log(`PASS ${label}`);
  else {
    console.error(`FAIL ${label}`);
    failed += 1;
  }
}
if (failed) process.exit(1);
