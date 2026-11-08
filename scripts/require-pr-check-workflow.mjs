// Keep every publication entry point behind the same fail-closed source proof.
export function validatePrCheckGuard(workflow, job) {
  const errors = [];
  const require = (condition, message) => { if (!condition) errors.push(message); };
  const section = workflow.match(new RegExp(`^  ${job}:\\n[\\s\\S]*?(?=^  [a-zA-Z0-9_-]+:|$(?![\\s\\S]))`, "m"))?.[0] ?? "";
  const steps = section.split(/(?=^      - )/m).slice(1);
  const guards = steps.filter((step) => step.startsWith("      - name: Require successful tree-equivalent PR check\n"));
  const guard = guards[0] ?? "";
  require(guards.length === 1, "exactly one required PR-check guard must exist");
  require(/^    permissions:\n      contents: write\n      actions: read\n/m.test(section), "PR-check guard needs job-scoped actions: read");
  require(!/^    (?:if|continue-on-error):/m.test(section), "PR-check job cannot ignore or conditionally bypass its guard");
  require(!/^        (?:if|continue-on-error):/m.test(guard), "PR-check guard cannot be conditional or ignore failure");
  require(guard.includes("GH_TOKEN: ${{ github.token }}")
    && guard.includes("SOURCE_DEPLOY_KEY: ${{ secrets.SOURCE_DEPLOY_KEY }}"), "PR-check guard must bind Actions token and read-only source key");
  require(!/\|\|\s*(?:true|:)|continue-on-error|set \+e/.test(guard), "PR-check guard must propagate failure");
  if (job === "release") {
    require(steps[0] === guard && guards.length === 1, "PR-check guard must be the first release step, before secret preflight");
    require(guard.includes("SOURCE_SHA: ${{ inputs.source_sha }}"), "PR-check guard must verify the requested source SHA");
    const lines = guard.split("\n").map((line) => line.trim()).filter(Boolean);
    require(lines.includes('test "$GITHUB_REF" = "refs/heads/main"')
      && lines.includes('env -u SOURCE_DEPLOY_KEY gh api "repos/$GITHUB_REPOSITORY/contents/scripts/require-pr-check.mjs?ref=$GITHUB_SHA" \\')
      && lines.includes('--jq .content | base64 --decode > "$RUNNER_TEMP/require-pr-check.mjs"')
      && lines.includes('node "$RUNNER_TEMP/require-pr-check.mjs"')
      && lines.includes("set -euo pipefail"), "first release step must execute the guard from the exact workflow SHA");
    require(steps.findIndex((step) => step.includes("name: Release-Secret-Preflight")) > 0,
      "release secret preflight must follow the required PR-check guard");
    require((guard.match(/\$\{\{ secrets\./g) ?? []).length === 1, "only the read-only tree key may precede PR-check approval");
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
