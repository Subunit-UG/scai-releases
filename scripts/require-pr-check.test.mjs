import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, writeFileSync, readdirSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { requirePrCheck, sourceFromRun, requireJobs, privateTreeReader, main, REQUIRED_JOBS } from "./require-pr-check.mjs";
import { validatePrCheckGuard } from "./require-pr-check-workflow.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const read = (file) => readFileSync(join(ROOT, file), "utf8");
const fixture = (name) => JSON.parse(read(`scripts/fixtures/pr-check/${name}.json`));
const GREEN = "d35c559238029a8b85dc94c2823919274d3ec518";
const UNCHECKED = "574c116982669ccf7945653385595e4db62e4917";
const NOW = new Date("2026-11-08T12:00:00Z");

function harness() {
  const run = fixture("41977805327-run");
  const state = {
    run, runs: [run], jobs: fixture("41977805327-jobs").jobs,
    workflow: fixture("workflow"), trees: fixture("trees"), calls: [],
  };
  state.api = async (path) => {
    state.calls.push(path);
    if (path.endsWith("/actions/workflows/pr-check.yml")) return state.workflow;
    if (path.includes("/runs?")) return { total_count: state.runs.length, workflow_runs: state.runs };
    if (path.includes("/jobs?")) return { total_count: state.jobs.length, jobs: state.jobs };
    if (path.endsWith(`/runs/${run.id}`)) return state.run;
    throw new Error("Unexpected fixture API request");
  };
  state.verify = (sourceSha = GREEN, api = state.api) => requirePrCheck({
    api, sourceSha, now: NOW, treeFor: async (sha) => state.trees[sha],
  });
  return state;
}

test("recorded successful PR check approves d35c5592 and its mandatory jobs", async () => {
  const h = harness();
  const proof = await h.verify();
  assert.equal(proof.runId, 41977805327);
  assert.equal(proof.tree, h.trees[GREEN]);
  assert.ok(h.calls.some((path) => path.includes("/attempts/1/jobs?")));
  assert.ok(h.calls[1].includes("created=%3E%3D2026-10-09"));
});

test("recorded build success is not a PR check and cannot approve 574c1169", async () => {
  const h = harness();
  const release = fixture("42248826208-run");
  assert.equal(release.conclusion, "success");
  assert.equal(sourceFromRun(release, h.workflow.id), null);
  // The last green PR run and the successful release both exist; neither
  // proves the untested tree. This is the actual historical bypass shape.
  h.runs.push(release);
  await assert.rejects(h.verify(UNCHECKED), /No unique tree-equivalent/);
});

test("squash commit with a different SHA and identical tree is accepted", async () => {
  const h = harness();
  const squash = "b".repeat(40);
  h.trees[squash] = h.trees[GREEN];
  assert.equal((await h.verify(squash)).checkedSha, GREEN);
});

test("rejects equal SHA prefixes with different trees", async () => {
  const h = harness();
  const other = GREEN.slice(0, 8) + "b".repeat(32);
  h.trees[other] = "c".repeat(40);
  await assert.rejects(h.verify(other), /No unique tree-equivalent/);
});

test("rejects a failed run", async () => {
  const h = harness();
  h.run.conclusion = "failure";
  await assert.rejects(h.verify(), /No successful PR check/);
});

for (const conclusion of ["cancelled", "skipped", "neutral", null, "timed_out"]) {
  test(`rejects run conclusion ${conclusion}`, async () => {
    const h = harness(); h.run.conclusion = conclusion;
    await assert.rejects(h.verify(), /No successful PR check/);
  });
}

for (const [field, value] of [
  ["event", "push"], ["head_branch", "feature/guard"], ["path", ".github/workflows/build-all.yml"],
  ["workflow_id", 1], ["status", "in_progress"], ["run_attempt", 0],
  ["repository", { full_name: "other/scai-releases" }], ["head_repository", { full_name: "other/scai-releases" }],
  ["created_at", "2026-09-01T00:00:00Z"], ["created_at", "2027-01-01T00:00:00Z"],
]) {
  test(`rejects foreign, expired or malformed run: ${field}=${JSON.stringify(value)}`, async () => {
    const h = harness(); h.run[field] = value;
    await assert.rejects(h.verify(), /No successful PR check/);
  });
}

for (const title of [
  `SCAI PR · ${GREEN.slice(0, 8)} · 4d6d8b21-6364-4861-a9f5-2395adb15185`,
  `SCAI PR · ${GREEN.toUpperCase()} · 4d6d8b21-6364-4861-a9f5-2395adb15185`,
  `prefix SCAI PR · ${GREEN} · 4d6d8b21-6364-4861-a9f5-2395adb15185`,
  `SCAI PR · ${GREEN} · 4d6d8b21-6364-1861-a9f5-2395adb15185`,
  `SCAI PR · ${GREEN} · 4d6d8b21-6364-4861-a9f5-2395adb15185\nignored`,
]) {
  test(`rejects non-exact source/request title: ${title.slice(0, 25)}`, async () => {
    const h = harness(); h.run.display_title = title;
    await assert.rejects(h.verify(), /No successful PR check/);
  });
}

for (const job of REQUIRED_JOBS) {
  for (const conclusion of ["skipped", "failure", "cancelled"]) {
    test(`rejects ${conclusion} mandatory job ${job}`, async () => {
      const h = harness(); h.jobs.find((j) => j.name === job).conclusion = conclusion;
      await assert.rejects(h.verify(), /job is missing, skipped or unsuccessful/);
    });
  }
}

for (const proof of ["Host-Restore explizit mit WebKit beweisen", "Meet-Plugin visuell und interaktiv beweisen"]) {
  test(`rejects skipped mandatory browser proof: ${proof}`, async () => {
    const h = harness();
    h.jobs.find((j) => j.name === "tsc + vite + cargo test").steps.find((s) => s.name === proof).conclusion = "skipped";
    await assert.rejects(h.verify(), /Required browser proof/);
  });
}

test("rejects missing, duplicated, unknown, empty and stale jobs", async () => {
  for (const mutate of [
    (h) => h.jobs.shift(),
    (h) => h.jobs.push({ ...h.jobs[0], id: 99999 }),
    (h) => { h.jobs[0].name = "unexpected"; },
    (h) => { h.jobs[0].steps = []; },
    (h) => { h.jobs[0].run_attempt = 2; },
    (h) => { h.jobs[0].head_sha = "a".repeat(40); },
    (h) => { h.jobs[0].run_id++; },
  ]) {
    const h = harness(); mutate(h);
    await assert.rejects(h.verify());
  }
});

test("optional Trace matrix must be explicitly skipped or fully green", () => {
  const h = harness();
  const skipped = h.jobs.pop();
  assert.equal(skipped.conclusion, "skipped");
  assert.throws(() => requireJobs(h.jobs, h.run), /Incomplete optional Trace/);
  const expanded = ["linux-core", "macos-arm64", "macos-x64", "windows-x64"].map((label, index) => ({
    ...skipped, id: 80000 + index, name: `Trace Standalone prüfen (${label})`, conclusion: "success",
  }));
  assert.doesNotThrow(() => requireJobs([...h.jobs, ...expanded], h.run));
  assert.throws(() => requireJobs([...h.jobs, ...expanded, skipped], h.run), /Incomplete optional Trace/);
  expanded[0].conclusion = "skipped";
  assert.throws(() => requireJobs([...h.jobs, ...expanded], h.run), /job is missing, skipped or unsuccessful/);
});

test("API failure at every stage rejects approval", async () => {
  const successful = harness(); await successful.verify();
  for (let i = 0; i < successful.calls.length; i++) {
    const h = harness(); let call = 0;
    await assert.rejects(h.verify(GREEN, async (path) => {
      if (call++ === i) throw new Error("API unavailable");
      return h.api(path);
    }), /API unavailable/);
  }
});

test("run retries or changed conclusion invalidate the verification snapshot", async () => {
  for (const change of ["run_attempt", "conclusion", "head_sha"]) {
    for (const nth of [1, 2]) {
      const h = harness(); let reads = 0;
      await assert.rejects(h.verify(GREEN, async (path) => {
        const data = await h.api(path);
        if (path.endsWith(`/runs/${h.run.id}`) && ++reads === nth) {
          return { ...data, [change]: change === "run_attempt" ? 2 : change === "head_sha" ? "c".repeat(40) : "failure" };
        }
        return data;
      }), /run changed/);
    }
  }
});

test("multiple tree-equivalent successful runs are ambiguous", async () => {
  const h = harness(); h.runs.push({ ...h.run, id: h.run.id + 1 });
  await assert.rejects(h.verify(), /No unique tree-equivalent/);
});

test("pagination follows a second run page instead of selecting the first page", async () => {
  const h = harness();
  const first = Array.from({ length: 100 }, (_, index) => ({ ...h.run, id: index + 1, conclusion: "failure" }));
  const proof = await h.verify(GREEN, async (path) => path.includes("/runs?")
    ? { total_count: 101, workflow_runs: path.endsWith("page=1") ? first : [h.run] }
    : h.api(path));
  assert.equal(proof.runId, h.run.id);
});

test("pagination rejects overflow, incomplete pages, duplicate IDs and changing totals", async () => {
  for (const data of [
    { total_count: 1001, workflow_runs: [] },
    { total_count: 2, workflow_runs: [harness().run] },
    { total_count: 2, workflow_runs: [harness().run, harness().run] },
    { total_count: "1", workflow_runs: [harness().run] },
    { total_count: 1, workflow_runs: null },
  ]) {
    const h = harness();
    await assert.rejects(h.verify(GREEN, async (path) => path.includes("/runs?") ? data : h.api(path)));
  }
  const h = harness();
  await assert.rejects(h.verify(GREEN, async (path) => path.includes("/runs?") ? {
    total_count: path.endsWith("page=1") ? 101 : 102,
    workflow_runs: Array.from({ length: 100 }, (_, index) => ({ ...h.run, id: index + 1, conclusion: "failure" })),
  } : h.api(path)), /pagination changed/);
});

test("job pagination is bounded and cannot hide failed jobs on page two", async () => {
  const h = harness();
  await assert.rejects(h.verify(GREEN, async (path) => path.includes("/jobs?") ? {
    total_count: 101,
    jobs: path.endsWith("page=1")
      ? Array.from({ length: 100 }, (_, index) => ({ ...h.jobs[0], id: index + 1, name: `unknown-${index}` }))
      : [{ ...h.jobs[0], id: 101, conclusion: "failure" }],
  } : h.api(path)), /PR-check job/);
});

test("invalid source, workflow and tree identities fail closed", async () => {
  for (const sha of ["main", "", GREEN.toUpperCase(), `${GREEN}\n`, "--help"]) await assert.rejects(harness().verify(sha));
  for (const value of [null, "bad-tree", "a".repeat(39)]) {
    const h = harness(); h.trees[GREEN] = value; await assert.rejects(h.verify(), /Invalid source tree/);
  }
  const h = harness(); h.workflow.state = "disabled_manually";
  await assert.rejects(h.verify(), /workflow identity/);
});

test("CLI rejects a foreign workflow branch or repository before using credentials", async () => {
  await assert.rejects(main({ GITHUB_REPOSITORY: "Subunit-UG/scai-releases", GITHUB_REF: "refs/heads/feature" }), /main workflow branch/);
  await assert.rejects(main({ GITHUB_REPOSITORY: "other/repo", GITHUB_REF: "refs/heads/main" }), /main workflow branch/);
});

const build = read(".github/workflows/build-all.yml");
const publish = read(".github/workflows/publish-approved.yml");

test("release guard is present as the first release step", () => {
  assert.deepEqual(validatePrCheckGuard(build, "release"), []);
});

test("release guard precedes secret preflight", () => {
  assert.deepEqual(validatePrCheckGuard(build, "release"), []);
  assert.ok(build.indexOf("name: Require successful tree-equivalent PR check") < build.indexOf("name: Release-Secret-Preflight"));
});

test("publication rechecks PR CI for manifest source before draft access", () => {
  assert.deepEqual(validatePrCheckGuard(publish, "publish"), []);
  const missing = publish.replace("run: node scripts/require-pr-check.mjs", "run: true");
  assert.ok(validatePrCheckGuard(missing, "publish").length > 0);
});

test("workflow guard rejects bypass, source substitution and mutable bootstrap", () => {
  for (const [before, after] of [
    ["id: pr_check", "id: pr_check\n        if: false"],
    ["id: pr_check", "id: pr_check\n        continue-on-error: true"],
    ['node "$RUNNER_TEMP/require-pr-check.mjs"', 'node "$RUNNER_TEMP/require-pr-check.mjs" || true'],
    ["SOURCE_SHA: ${{ inputs.source_sha }}", "SOURCE_SHA: arbitrary"],
    ["?ref=$GITHUB_SHA", "?ref=main"],
    ["actions: read", "actions: write"],
  ]) {
    assert.ok(validatePrCheckGuard(build.replace(before, after), "release").length > 0, before);
  }
});

test("mandatory job policy matches the workflow and unconditional browser proofs", () => {
  const workflow = read(".github/workflows/pr-check.yml");
  for (const name of REQUIRED_JOBS.slice(0, 2)) assert.ok(workflow.includes(`name: ${name}\n`));
  const native = workflow.match(/^  native-trace:\n[\s\S]*?(?=^  [a-z-]+:|$(?![\s\S]))/m)?.[0] ?? "";
  assert.deepEqual([...native.matchAll(/label: ([a-z0-9-]+)/g)].map((m) => m[1]).sort(), ["macos-arm64", "windows-x64"]);
  for (const name of ["Host-Restore explizit mit WebKit beweisen", "Meet-Plugin visuell und interaktiv beweisen"]) {
    const step = workflow.split(/(?=^      - name:)/m).find((s) => s.startsWith(`      - name: ${name}\n`));
    assert.ok(step); assert.doesNotMatch(step, /^        (?:if|continue-on-error):/m);
  }
  assert.match(workflow, /if: inputs\.trace_ref != '' && needs\.preflight\.result == 'success'/);
});

test("tree reader compares real Git trees without private checkout or credential inheritance", () => {
  const dir = mkdtempSync(join(tmpdir(), "pr-tree-test-"));
  try {
    const git = spawnSync("which", ["git"], { encoding: "utf8" }).stdout.trim();
    const source = join(dir, "origin.git");
    const exec = (args, input) => {
      const result = spawnSync(git, args, { encoding: "utf8", input, env: {
        ...process.env, GIT_AUTHOR_NAME: "Fixture", GIT_AUTHOR_EMAIL: "fixture@example.invalid",
        GIT_COMMITTER_NAME: "Fixture", GIT_COMMITTER_EMAIL: "fixture@example.invalid",
      } });
      assert.equal(result.status, 0, result.stderr); return result.stdout.trim();
    };
    exec(["init", "--bare", source]);
    const tree = exec(["-C", source, "mktree"], "");
    const a = exec(["-C", source, "commit-tree", tree], "head\n");
    const b = exec(["-C", source, "commit-tree", tree, "-p", a], "squash\n");
    const bin = join(dir, "bin"); mkdirSync(bin);
    const script = (name, code) => writeFileSync(join(bin, name), `#!${process.execPath}\n${code}`, { mode: 0o755 });
    script("ssh-keyscan", 'console.log("github.com ssh-ed25519 fixture");');
    script("ssh-keygen", 'console.log("256 SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU github.com");');
    script("git", `
      const {spawnSync}=require('node:child_process');
      if(process.env.SOURCE_DEPLOY_KEY || process.env.GH_TOKEN || process.env.GITHUB_TOKEN) process.exit(42);
      const args=process.argv.slice(2).map(a=>a==='git@github.com:Subunit-UG/scai-app.git'?${JSON.stringify(source)}:a);
      if(args.includes('checkout')) process.exit(43);
      const r=spawnSync(${JSON.stringify(git)},args,{encoding:'utf8'});
      process.stdout.write(r.stdout||''); process.stderr.write(r.stderr||''); process.exit(r.status??1);
    `);
    const env = { ...process.env, RUNNER_TEMP: dir, PATH: `${bin}:${process.env.PATH}`, SOURCE_DEPLOY_KEY: "fixture-key", GH_TOKEN: "fixture-token", GITHUB_TOKEN: "fixture-token" };
    const reader = privateTreeReader(env);
    try { assert.equal(reader.treeFor(a), tree); assert.equal(reader.treeFor(b), tree); }
    finally { reader.close(); }
    assert.ok(!readdirSync(dir).some((name) => name.startsWith("scai-pr-check-")));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
