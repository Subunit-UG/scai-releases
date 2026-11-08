// Keep every publication entry point behind the same fail-closed source proof.
import { REQUIRED_JOBS, REQUIRED_PROOFS, OPTIONAL_TRACE, SKIPPED_TRACE } from "./require-pr-check.mjs";

function jobSections(workflow) {
  const jobs = workflow.slice(workflow.indexOf("\njobs:\n") + 7);
  return [...jobs.matchAll(/^  ([a-zA-Z0-9_-]+):\n([\s\S]*?)(?=^  [a-zA-Z0-9_-]+:|$(?![\s\S]))/gm)];
}

export function validateReleaseEnvironments(workflow) {
  const errors = [];
  const sensitive = /(?:[A-Z0-9_]*TAURI_SIGNING_|APPLE_|WINDOWS_CERTIFICATE|AZURE_|SUBUNIT_APP_PRIVATE_KEY)/;
  const usesAuthority = (text) => [...text.matchAll(/\$\{\{([\s\S]*?)\}\}/g)].some((expression) =>
    [...expression[1].matchAll(/secrets\.([A-Z0-9_]+)|secrets\[['"]([A-Z0-9_]+)['"]\]/g)]
      .some((match) => sensitive.test(match[1] ?? match[2])) || /secrets\s*\[/.test(expression[1]));
  const global = workflow.slice(0, workflow.indexOf("\njobs:\n"));
  for (const [, id, body] of jobSections(workflow)) {
    if ((usesAuthority(global) || usesAuthority(body))
        && (body.match(/^    environment:.*$/gm) ?? []).join("\n") !== "    environment: release") {
      errors.push(`${id}: signing and publication credentials require exactly environment: release`);
    }
  }
  return errors;
}

// Compare the complete API-visible policy to the real workflow at this commit,
// including both expanded matrices, the skipped placeholder and proof steps.
export function validatePrCheckPolicy(workflow) {
  const errors = [];
  const jobs = new Map(jobSections(workflow).map(([, id, body]) => [id, body]));
  const require = (condition, message) => { if (!condition) errors.push(message); };
  const name = (id) => jobs.get(id)?.match(/^    name: (.+)$/m)?.[1];
  const labels = (id) => [...(jobs.get(id)?.split(/^    steps:/m)[0] ?? "").matchAll(/^            label: (.+)$/gm)].map((m) => m[1]);
  const expanded = (id) => labels(id).map((label) => name(id)?.replace("${{ matrix.label }}", label));
  const equal = (a, b) => JSON.stringify([...a].sort()) === JSON.stringify([...b].sort());
  require(equal(jobs.keys(), ["preflight", "check", "native-trace", "trace-standalone"]), "PR-check job inventory changed");
  require(equal([name("preflight"), name("check"), ...expanded("native-trace")], REQUIRED_JOBS), "mandatory PR-check job names or native matrix labels changed");
  require(name("trace-standalone") === SKIPPED_TRACE && equal(expanded("trace-standalone"), OPTIONAL_TRACE), "Trace job name or matrix labels changed");
  for (const proof of REQUIRED_PROOFS) {
    const steps = (jobs.get("check") ?? "").split(/(?=^      - )/m)
      .filter((step) => step.startsWith(`      - name: ${proof}\n`));
    require(steps.length === 1 && !/^        (?:if|continue-on-error):/m.test(steps[0]), "mandatory browser proof name or execution changed");
  }
  require(jobs.get("trace-standalone")?.includes("    if: inputs.trace_ref != '' && needs.preflight.result == 'success'\n"), "optional Trace condition changed");
  return errors;
}

export function validatePrCheckGuard(workflow, job) {
  const errors = [];
  const require = (condition, message) => { if (!condition) errors.push(message); };
  const section = workflow.match(new RegExp(`^  ${job}:\\n[\\s\\S]*?(?=^  [a-zA-Z0-9_-]+:|$(?![\\s\\S]))`, "m"))?.[0] ?? "";
  const steps = section.split(/(?=^      - )/m).slice(1);
  const guards = steps.filter((step) => step.startsWith("      - name: Require successful tree-equivalent PR check\n"));
  const guard = guards[0] ?? "";
  const permissions = section.match(/^    permissions:\n((?:      [a-z-]+:[^\n]*\n)+)/m)?.[1] ?? "";
  require(guards.length === 1, "exactly one required PR-check guard must exist");
  require(/^      actions: read$/m.test(permissions) && /^      contents: write$/m.test(permissions), "PR-check guard needs job-scoped actions: read");
  require(/^    environment: release$/m.test(section), "publication job must use environment: release");
  if (job !== "manifest") require(!/^    (?:if|continue-on-error):/m.test(section), "PR-check job cannot ignore or conditionally bypass its guard");
  require(!/^        continue-on-error:/m.test(guard), "PR-check guard cannot ignore failure");
  require(job === "manifest" ? /^        if: inputs.publish_update$/m.test(guard) : !/^        if:/m.test(guard), "PR-check guard condition must match its publication path");
  require(guard.includes("GH_TOKEN: ${{ github.token }}")
    && guard.includes("SOURCE_DEPLOY_KEY: ${{ secrets.SOURCE_DEPLOY_KEY }}"), "PR-check guard must bind Actions token and read-only source key");
  require(!/\|\|\s*(?:true|:)|continue-on-error|set \+e/.test(guard), "PR-check guard must propagate failure");
  require(guard.includes("PR_CHECK_TEMP: ${{ runner.temp }}/required-pr-check"), "PR-check guard must isolate its temporary credentials");
  require(steps.some((step) => /^        if: always\(\)$/m.test(step)
    && /^        run: rm -rf -- "\$RUNNER_TEMP\/required-pr-check"$/m.test(step)), "PR-check credentials need independent always cleanup");
  if (job === "release") {
    require(steps[0] === guard && guards.length === 1, "PR-check guard must be the first release step, before secret preflight");
    require(guard.includes("SOURCE_SHA: ${{ inputs.source_sha }}"), "PR-check guard must verify the requested source SHA");
    const lines = guard.split("\n").map((line) => line.trim()).filter(Boolean);
    require(lines.includes('test "$GITHUB_REF" = "refs/heads/main"')
      && lines.includes('env -u SOURCE_DEPLOY_KEY gh api "repos/$GITHUB_REPOSITORY/contents/scripts/require-pr-check.mjs?ref=$GITHUB_SHA" \\')
      && lines.includes('--jq .content | env -u SOURCE_DEPLOY_KEY -u GH_TOKEN -u GITHUB_TOKEN base64 --decode > "$RUNNER_TEMP/require-pr-check.mjs"')
      && lines.includes('node "$RUNNER_TEMP/require-pr-check.mjs"')
      && lines.includes("set -euo pipefail"), "first release step must execute the guard from the exact workflow SHA");
    require(steps.findIndex((step) => step.includes("name: Release-Secret-Preflight")) > 0,
      "release secret preflight must follow the required PR-check guard");
    require((guard.match(/\$\{\{ secrets\./g) ?? []).length === 1, "only the read-only tree key may precede PR-check approval");
  } else if (job === "manifest") {
    require(guard.includes("SOURCE_SHA: ${{ needs.release.outputs.source_sha }}")
      && /^        run: node scripts\/require-pr-check\.mjs\s*$/m.test(guard), "updater must recheck the same immutable source with the same guard");
    const index = steps.indexOf(guard);
    require(index >= 0 && steps[index + 1]?.startsWith("      - name: Technischen Stand verifizieren und optional als Updater veröffentlichen\n")
      && steps[index + 1].includes('gh release edit "$TAG"'), "updater PR-check guard must immediately precede the publishing step");
  } else {
    require(guard.includes("SOURCE_SHA: ${{ steps.gate.outputs.source_sha }}")
      && /^        run: node scripts\/require-pr-check\.mjs\s*$/m.test(guard), "publisher must verify the manifest-bound source SHA");
    const guardIndex = steps.indexOf(guard);
    require(guardIndex > steps.findIndex((step) => step.includes("id: gate")) && guardIndex >= 0
      && steps.findIndex((step) => step.includes("gh release")) > guardIndex,
    "publisher PR-check guard must follow manifest validation and precede draft access or publication");
  }
  return errors;
}
