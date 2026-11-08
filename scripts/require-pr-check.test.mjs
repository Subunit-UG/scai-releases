import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, writeFileSync, readdirSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { spawnSync, spawn } from "node:child_process";
import { EventEmitter, once } from "node:events";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { requirePrCheck, sourceFromRun, requireJobs, privateTreeReader, main, REQUIRED_JOBS, REQUIRED_PROOFS } from "./require-pr-check.mjs";
import { validatePrCheckGuard, validatePrCheckPolicy, validateReleaseEnvironments } from "./require-pr-check-workflow.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const read = (file) => readFileSync(join(ROOT, file), "utf8");
const fixture = (name) => JSON.parse(read(`scripts/fixtures/pr-check/${name}.json`));
const GREEN = "d35c559238029a8b85dc94c2823919274d3ec518";
const UNCHECKED = "574c116982669ccf7945653385595e4db62e4917";
const NOW = new Date("2026-11-08T12:00:00Z");

function runPage(path, runs) {
  const query = new URL(`https://fixture.invalid/${path}`).searchParams;
  const [start, end] = query.get("created").split("..").map(Date.parse);
  const window = runs.filter((run) => Date.parse(run.created_at) >= start && Date.parse(run.created_at) <= end);
  const page = Number(query.get("page"));
  return { total_count: window.length, workflow_runs: structuredClone(window.slice((page - 1) * 100, page * 100)) };
}

function harness() {
  const run = fixture("41977805327-run");
  const state = {
    run, runs: [run], jobs: fixture("41977805327-jobs").jobs,
    workflow: fixture("workflow"), trees: fixture("trees"), calls: [], treeCalls: [], batches: [],
  };
  state.api = async (path) => {
    state.calls.push(path);
    if (path.endsWith("/actions/workflows/pr-check.yml")) return state.workflow;
    if (path.includes("/runs?")) return runPage(path, state.runs);
    if (path.includes("/jobs?")) return { total_count: state.jobs.length, jobs: state.jobs };
    const id = /\/runs\/([0-9]+)$/.exec(path)?.[1];
    if (id) return state.runs.find((item) => item.id === Number(id));
    throw new Error("Unexpected fixture API request");
  };
  state.verify = (sourceSha = GREEN, api = state.api) => requirePrCheck({
    api, sourceSha, now: NOW,
    treeFor: async (sha) => { state.treeCalls.push(sha); return state.trees[sha]; },
    prefetchTrees: async (shas) => { state.batches.push(shas); },
  });
  state.select = (selected) => {
    for (const job of state.jobs) {
      job.run_id = selected.id;
      job.run_attempt = selected.run_attempt;
      job.head_sha = selected.head_sha;
    }
  };
  return state;
}

test("recorded successful PR check approves d35c5592 and its mandatory jobs", async () => {
  const h = harness();
  const proof = await h.verify();
  assert.equal(proof.runId, 41977805327);
  assert.equal(proof.tree, h.trees[GREEN]);
  assert.ok(h.calls.some((path) => path.includes("/attempts/1/jobs?")));
  assert.ok(!h.calls.some((path) => path.includes("2026-10-09T12%3A00%3A00.000Z")), "stop before irrelevant history");
});

test("recorded build success is not a PR check and cannot approve 574c1169", async () => {
  const h = harness();
  const release = fixture("42248826208-run");
  assert.equal(release.conclusion, "success");
  assert.equal(sourceFromRun(release, h.workflow.id), null);
  // The last green PR run and the successful release both exist; neither
  // proves the untested tree. This is the actual historical bypass shape.
  h.runs.push(release);
  await assert.rejects(h.verify(UNCHECKED), /No tree-equivalent/);
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
  await assert.rejects(h.verify(other), /No tree-equivalent/);
});

test("rejects a failed run", async () => {
  const h = harness();
  h.run.conclusion = "failure";
  await assert.rejects(h.verify(), /Latest tree-equivalent PR check is unsuccessful/);
});

for (const conclusion of ["cancelled", "skipped", "neutral", null, "timed_out"]) {
  test(`rejects run conclusion ${conclusion}`, async () => {
    const h = harness(); h.run.conclusion = conclusion;
    await assert.rejects(h.verify(), /Latest tree-equivalent PR check is unsuccessful/);
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
    await assert.rejects(h.verify(), /No completed PR check/);
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
    await assert.rejects(h.verify(), /No completed PR check/);
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
    for (const nth of [1, 2, 3]) {
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

test("two green tree-equivalent runs pass with the newest by created_at", async () => {
  const h = harness();
  // A lower ID with a later creation time must win, regardless of API order.
  const newest = { ...h.run, id: h.run.id - 1, created_at: "2026-11-05T08:02:47Z",
    display_title: h.run.display_title.replace(GREEN, UNCHECKED) };
  h.runs.push(newest);
  h.trees[UNCHECKED] = h.trees[GREEN];
  h.select(newest);
  assert.equal((await h.verify()).runId, newest.id);
  assert.deepEqual(h.batches, [[UNCHECKED]]);
});

test("green then red tree-equivalent runs fail on the newest", async () => {
  const h = harness();
  h.runs.push({ ...h.run, id: h.run.id + 1, conclusion: "failure",
    display_title: h.run.display_title.replace(GREEN, UNCHECKED) });
  h.trees[UNCHECKED] = h.trees[GREEN];
  await assert.rejects(h.verify(), /Latest tree-equivalent PR check is unsuccessful/);
});

test("red then green tree-equivalent runs pass on the newest", async () => {
  const h = harness();
  const newest = { ...h.run, id: h.run.id + 1 };
  h.run.conclusion = "failure";
  h.runs.unshift(newest);
  h.select(newest);
  assert.equal((await h.verify()).runId, newest.id);
});

test("equal creation timestamps use descending run ID deterministically", async () => {
  for (const reverse of [false, true]) {
    const h = harness();
    const newest = { ...h.run, id: h.run.id + 1 };
    h.runs.push(newest);
    if (reverse) h.runs.reverse();
    h.select(newest);
    assert.equal((await h.verify()).runId, newest.id);
  }
});

test("newer cancelled or skipped outcomes invalidate older green evidence", async () => {
  for (const conclusion of ["cancelled", "skipped", "neutral", "timed_out", null]) {
    const h = harness();
    h.runs.push({ ...h.run, id: h.run.id + 1, conclusion });
    await assert.rejects(h.verify(), /Latest tree-equivalent PR check is unsuccessful/);
  }
});

test("pending runs are ignored while the latest completed evidence is checked", async () => {
  for (const status of ["queued", "in_progress", "waiting"]) {
    const h = harness();
    h.runs.push({ ...h.run, id: h.run.id + 1, status, conclusion: null });
    assert.equal((await h.verify()).runId, h.run.id);
  }
});

test("candidate refresh rejects a younger run completing during verification", async () => {
  for (const conclusion of ["failure", "cancelled"]) {
    for (const during of ["tree", "jobs"]) {
      const h = harness();
      const younger = { ...h.run, id: h.run.id + 1, status: "in_progress", conclusion: null,
        display_title: h.run.display_title.replace(GREEN, UNCHECKED) };
      h.trees[UNCHECKED] = h.trees[GREEN];
      h.runs.push(younger);
      const finish = () => { younger.status = "completed"; younger.conclusion = conclusion; };
      await assert.rejects(requirePrCheck({ sourceSha: GREEN, now: NOW,
        api: async (path) => { if (during === "jobs" && path.includes("/jobs?")) finish(); return h.api(path); },
        treeFor: async (sha) => { if (during === "tree") finish(); return h.trees[sha]; },
        prefetchTrees: async () => {},
      }), /Latest tree-equivalent PR check is unsuccessful/);
    }
  }
});

test("candidate refresh uses the current upper time bound for newly created runs", async () => {
  const h = harness();
  let elapsed = 0;
  await assert.rejects(requirePrCheck({ sourceSha: GREEN, now: NOW, clock: () => elapsed,
    api: async (path) => {
      if (path.includes("/jobs?")) {
        elapsed = 2000;
        h.runs.push({ ...h.run, id: h.run.id + 1, created_at: "2026-11-08T12:00:01Z", conclusion: "failure" });
      }
      return h.api(path);
    }, treeFor: async (sha) => h.trees[sha],
  }), /Latest tree-equivalent PR check is unsuccessful/);
});

test("search stops at the first matching completed window", async () => {
  const h = harness();
  h.run.created_at = "2026-11-08T11:59:00Z";
  h.runs.push({ ...h.run, id: h.run.id - 1, created_at: "2026-11-07T10:00:00Z",
    display_title: h.run.display_title.replace(GREEN, UNCHECKED) });
  assert.equal((await h.verify()).runId, h.run.id);
  const lists = h.calls.filter((path) => path.includes("/runs?"));
  assert.equal(lists.length, 2, "one search window and one fresh final range");
  assert.deepEqual(h.treeCalls, [GREEN]);
  assert.deepEqual(h.batches, []);
});

test("within a complete window the first matching tree stops older comparisons", async () => {
  const h = harness();
  const squash = "b".repeat(40);
  h.trees[squash] = h.trees[GREEN];
  h.runs.push({ ...h.run, id: h.run.id - 1, display_title: h.run.display_title.replace(GREEN, UNCHECKED) });
  assert.equal((await h.verify(squash)).runId, h.run.id);
  assert.deepEqual(h.treeCalls, [squash, GREEN], "do not resolve older candidate trees");
});

test("younger matching failure during the second historical window blocks PASS", async () => {
  const h = harness();
  const younger = { ...h.run, id: h.run.id + 1, created_at: "2026-11-08T11:59:00Z",
    status: "in_progress", conclusion: null };
  h.runs.push(younger);
  let lists = 0;
  await assert.rejects(h.verify(GREEN, async (path) => {
    if (path.includes("/runs?") && ++lists === 2) {
      younger.status = "completed"; younger.conclusion = "failure";
    }
    return h.api(path);
  }), /Latest tree-equivalent PR check is unsuccessful/);
  assert.equal(lists, 5, "four search windows followed by one fresh range");
});

test("new successful run created and completed during search replaces old evidence", async () => {
  const h = harness();
  let elapsed = 0, lists = 0;
  const newer = { ...h.run, id: h.run.id + 1, created_at: "2026-11-08T12:00:01Z" };
  const proof = await requirePrCheck({ sourceSha: GREEN, now: NOW, clock: () => elapsed,
    api: async (path) => {
      if (path.includes("/runs?") && ++lists === 2) { elapsed = 2000; h.runs.push(newer); }
      if (path.includes(`/runs/${newer.id}`)) h.select(newer);
      return h.api(path);
    }, treeFor: async (sha) => h.trees[sha],
  });
  assert.equal(proof.runId, newer.id);
  assert.equal(lists, 5, "one final range and no later enumeration");
  assert.deepEqual(h.calls.slice(-3).map((path) => path.replace(/\?.*$/, "")), [
    `repos/Subunit-UG/scai-releases/actions/runs/${newer.id}`,
    `repos/Subunit-UG/scai-releases/actions/runs/${newer.id}/attempts/1/jobs`,
    `repos/Subunit-UG/scai-releases/actions/runs/${newer.id}`,
  ]);
});

test("final range is fully paginated and rejects a younger failure on page two", async () => {
  const h = harness();
  h.run.created_at = "2026-11-08T11:59:00Z";
  let added = false;
  await assert.rejects(h.verify(GREEN, async (path) => {
    if (!added && path.includes("/jobs?")) {
      added = true;
      h.runs.push(...Array.from({ length: 100 }, (_, index) => ({ ...h.run,
        id: h.run.id + index + 1, conclusion: index === 99 ? "failure" : "success" })));
    }
    return h.api(path);
  }), /Latest tree-equivalent PR check is unsuccessful/);
  assert.ok(h.calls.some((path) => path.includes("/runs?") && path.endsWith("page=2")));
});

test("replacement evidence must pass its own jobs and final attempt checks", async () => {
  for (const broken of ["jobs", "attempt"]) {
    const h = harness();
    const newer = { ...h.run, id: h.run.id + 1, created_at: "2026-11-08T11:59:00Z" };
    let added = false;
    await assert.rejects(h.verify(GREEN, async (path) => {
      if (!added && path.includes("/jobs?")) { added = true; h.runs.push(newer); }
      if (path.includes(`/runs/${newer.id}`)) {
        h.select(newer);
        if (broken === "jobs") h.jobs[0].conclusion = "skipped";
        else return { ...newer, run_attempt: 2 };
      }
      return h.api(path);
    }), broken === "jobs" ? /job is missing, skipped or unsuccessful/ : /run changed/);
  }
});

test("simple recent evidence uses at most eight API calls and two tree fetch batches", async () => {
  const h = harness();
  h.run.created_at = "2026-11-08T11:59:00Z";
  const squash = "b".repeat(40);
  h.trees[squash] = h.trees[GREEN];
  assert.equal((await h.verify(squash)).runId, h.run.id);
  assert.ok(h.calls.length <= 8, `API calls: ${h.calls.length}`);
  assert.deepEqual(h.treeCalls, [squash, GREEN]);
  assert.deepEqual(h.batches, [[GREEN]]);
});

test("four-second API latency passes the verification budget", async () => {
  const h = harness();
  h.run.created_at = "2026-11-08T11:59:00Z";
  let elapsed = 0;
  const proof = await requirePrCheck({ sourceSha: GREEN, now: NOW, clock: () => elapsed,
    api: async (path, { timeout }) => {
      assert.ok(timeout >= 4000); elapsed += 4000; return h.api(path);
    }, treeFor: async (sha) => h.trees[sha],
  });
  assert.equal(proof.runId, h.run.id);
  assert.equal(h.calls.length, 8);
  assert.equal(elapsed, 32000);
});

test("newest green run still requires its own mandatory jobs", async () => {
  const h = harness();
  const newest = { ...h.run, id: h.run.id + 1 };
  h.runs.push(newest); h.select(newest);
  h.jobs[0].conclusion = "skipped";
  await assert.rejects(h.verify(), /job is missing, skipped or unsuccessful/);
});

test("exact source SHA avoids older tree queries but not newer mismatches", async () => {
  const h = harness();
  h.runs.push({ ...h.run, id: h.run.id - 1, display_title: h.run.display_title.replace(GREEN, UNCHECKED) });
  assert.equal((await h.verify()).runId, h.run.id);
  assert.deepEqual(h.treeCalls, [GREEN]);
  assert.deepEqual(h.batches, []);
  h.runs.push({ ...h.run, id: h.run.id + 1, conclusion: "failure",
    display_title: h.run.display_title.replace(GREEN, UNCHECKED) });
  assert.equal((await h.verify()).runId, h.run.id);
  assert.deepEqual(h.batches, [[UNCHECKED]]);
});

test("non-exact candidate trees are deduplicated and prefetched once", async () => {
  const h = harness();
  const other = "a".repeat(40);
  h.trees[other] = "c".repeat(40);
  h.runs.push(...[UNCHECKED, other, UNCHECKED].map((sha, index) => ({ ...h.run,
    id: h.run.id + index + 1, display_title: h.run.display_title.replace(GREEN, sha) })));
  assert.equal((await h.verify()).runId, h.run.id);
  assert.deepEqual(h.batches, [[UNCHECKED, other]]);
});

test("batch failures or invalid checked trees never fall back to older evidence", async () => {
  const h = harness();
  h.runs.push({ ...h.run, id: h.run.id + 1, display_title: h.run.display_title.replace(GREEN, UNCHECKED) });
  h.trees[UNCHECKED] = null;
  await assert.rejects(h.verify(), /Invalid checked tree/);
  await assert.rejects(requirePrCheck({ api: h.api, sourceSha: GREEN, now: NOW,
    treeFor: async () => h.trees[GREEN],
    prefetchTrees: async () => { throw new Error("batch unavailable"); },
  }), /batch unavailable/);
});

test("pagination follows a second run page instead of selecting the first page", async () => {
  const h = harness();
  const first = Array.from({ length: 100 }, (_, index) => ({ ...h.run, id: index + 1, conclusion: "failure" }));
  h.runs = [...first, h.run];
  const proof = await h.verify();
  assert.equal(proof.runId, h.run.id);
  assert.ok(h.calls.some((path) => path.includes("/runs?") && path.endsWith("page=2")));
});

test("time-window search approves fresh exact evidence beyond 1000 runs", async () => {
  const h = harness();
  const older = Array.from({ length: 1100 }, (_, index) => ({ ...h.run, id: index + 1,
    created_at: new Date(Date.parse("2026-11-08T11:40:00Z") + index * 1000).toISOString(),
    conclusion: "failure", display_title: h.run.display_title.replace(GREEN, UNCHECKED) }));
  h.run.created_at = "2026-11-08T11:59:59Z";
  h.runs = [...older, h.run];
  assert.equal((await h.verify()).runId, h.run.id);
  assert.deepEqual(h.treeCalls, [GREEN]);
  assert.deepEqual(h.batches, []);
  assert.ok(h.calls.some((path) => path.includes("/runs?") && path.endsWith("page=6")), "subwindows must be fully paginated");
  const ranges = h.calls.filter((path) => path.includes("/runs?")).map((path) => new URL(`https://fixture.invalid/${path}`).searchParams.get("created"));
  assert.ok(new Set(ranges).size > 2, "the saturated day must be subdivided");
  assert.ok(ranges.every((range) => Date.parse(range.split("..")[0]) >= Date.parse("2026-11-07T12:00:01Z")), "older days are irrelevant");
});

test("time windows inspect all candidates and preserve younger red outcomes", async () => {
  const h = harness();
  h.runs.push(...Array.from({ length: 1001 }, (_, index) => ({ ...h.run, id: index + 1,
    created_at: new Date(Date.parse("2026-11-07T00:00:00Z") + index * 1000).toISOString(),
    display_title: h.run.display_title.replace(GREEN, UNCHECKED) })));
  h.runs.push({ ...h.run, id: h.run.id + 1, created_at: "2026-11-08T11:59:59Z", conclusion: "failure" });
  await assert.rejects(h.verify(), /Latest tree-equivalent PR check is unsuccessful/);
});

test("saturated one-second windows fail with an explicit recovery message", async () => {
  const h = harness();
  h.runs = Array.from({ length: 1001 }, (_, index) => ({ ...h.run, id: index + 1 }));
  await assert.rejects(h.verify(), /search window saturated at one second; retry/);
});

test("verification has a time budget instead of a total run-count ceiling", async () => {
  const h = harness();
  let elapsed = 0;
  const timeouts = [];
  await assert.rejects(requirePrCheck({ sourceSha: GREEN, now: NOW, clock: () => elapsed,
    api: async (path, options) => {
      timeouts.push(options.timeout);
      elapsed += 50000;
      return h.api(path);
    }, treeFor: async (sha) => h.trees[sha],
  }), /240-second resource budget; retry/);
  assert.deepEqual(timeouts, [60000, 60000, 60000, 60000, 40000]);
});

test("pagination rejects overflow, incomplete pages, duplicate IDs and changing totals", async () => {
  for (const data of [
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

test("direct updater publication immediately rechecks the same source", () => {
  assert.deepEqual(validatePrCheckGuard(build, "manifest"), []);
  const start = build.indexOf("      - name: Require successful tree-equivalent PR check", build.indexOf("  manifest:\n"));
  for (const [before, after] of [
    ["      - name: Require successful tree-equivalent PR check", "      - name: Removed guard"],
    ["SOURCE_SHA: ${{ needs.release.outputs.source_sha }}", "SOURCE_SHA: arbitrary"],
    ["if: inputs.publish_update", "if: false"],
    ["run: node scripts/require-pr-check.mjs", "run: true"],
  ]) {
    const mutant = build.slice(0, start) + build.slice(start).replace(before, after);
    assert.notDeepEqual(validatePrCheckGuard(mutant, "manifest"), [], before);
  }
});

test("signing and publication jobs use the protected release environment", () => {
  const required = {
    "build-all.yml": ["release", "build", "manifest"],
    "publish-approved.yml": ["publish"],
  };
  for (const filename of readdirSync(join(ROOT, ".github/workflows")).filter((name) => /\.ya?ml$/.test(name))) {
    const workflow = read(`.github/workflows/${filename}`);
    assert.deepEqual(validateReleaseEnvironments(workflow), [], filename);
    for (const job of required[filename] ?? []) {
      const section = workflow.match(new RegExp(`^  ${job}:\\n[\\s\\S]*?(?=^  [a-zA-Z0-9_-]+:|$(?![\\s\\S]))`, "m"))?.[0];
      assert.match(section ?? "", /^    environment: release$/m, `${filename}:${job}`);
    }
    // Every protected job must detect removal or substitution of its binding.
    for (const match of workflow.matchAll(/^    environment: release\n/gm)) {
      for (const replacement of ["", "    environment: arbitrary\n"]) {
        const mutant = workflow.slice(0, match.index) + replacement + workflow.slice(match.index + match[0].length);
        const sensitive = validateReleaseEnvironments(mutant);
        const guard = (required[filename] ?? []).flatMap((job) => validatePrCheckGuard(mutant, job));
        assert.ok(sensitive.length + guard.length > 0, `${filename}:${match.index}`);
      }
    }
  }
});

test("bootstrap decoder does not inherit the source key or Actions tokens", () => {
  assert.match(build, /\| env -u SOURCE_DEPLOY_KEY -u GH_TOKEN -u GITHUB_TOKEN base64 --decode/);
  assert.notDeepEqual(validatePrCheckGuard(build.replace("env -u SOURCE_DEPLOY_KEY -u GH_TOKEN -u GITHUB_TOKEN base64", "base64"), "release"), []);
  const dir = mkdtempSync(join(tmpdir(), "pr-bootstrap-test-"));
  try {
    const bin = join(dir, "bin"); mkdirSync(bin);
    const script = (name, code) => writeFileSync(join(bin, name), `#!${process.execPath}\n${code}`, { mode: 0o755 });
    script("gh", `
      if (process.env.SOURCE_DEPLOY_KEY || !process.env.GH_TOKEN) process.exit(42);
      console.log(Buffer.from('console.log("fixture-bootstrap-pass")').toString('base64'));
    `);
    script("base64", `
      if (process.env.SOURCE_DEPLOY_KEY || process.env.GH_TOKEN || process.env.GITHUB_TOKEN) process.exit(43);
      process.stdout.write(Buffer.from(require('node:fs').readFileSync(0,'utf8').trim(),'base64'));
    `);
    const guard = build.split(/(?=^      - )/m).find((step) => step.startsWith("      - name: Require successful tree-equivalent PR check\n"));
    const shell = guard.split("        run: |\n")[1].split("\n").map((line) => line.replace(/^          /, "")).join("\n");
    const result = spawnSync("bash", ["-c", shell], { encoding: "utf8", env: {
      ...process.env, PATH: `${bin}:${process.env.PATH}`, RUNNER_TEMP: dir,
      GITHUB_REF: "refs/heads/main", GITHUB_REPOSITORY: "Subunit-UG/scai-releases", GITHUB_SHA: "a".repeat(40),
      SOURCE_DEPLOY_KEY: "fixture-key", GH_TOKEN: "fixture-token", GITHUB_TOKEN: "fixture-token",
    } });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout.trim(), "fixture-bootstrap-pass");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("every PR guard has independent unconditional temporary-directory cleanup", () => {
  for (const [workflow, job] of [[build, "release"], [build, "manifest"], [publish, "publish"]]) {
    assert.deepEqual(validatePrCheckGuard(workflow, job), []);
    const mutant = workflow.replaceAll('run: rm -rf -- "$RUNNER_TEMP/required-pr-check"', "run: true");
    assert.notDeepEqual(validatePrCheckGuard(mutant, job), []);
  }
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
  assert.deepEqual(validatePrCheckPolicy(workflow), []);
  for (const [before, after] of [
    [REQUIRED_JOBS[0], "Renamed preflight"], [REQUIRED_JOBS[1], "Renamed checks"],
    ["SCAI + Trace nativ kompilieren", "Renamed native build"],
    ["Trace Standalone prüfen", "Renamed Trace check"],
    ...REQUIRED_PROOFS.map((proof) => [proof, `Renamed ${proof}`]),
  ]) {
    const prefix = REQUIRED_PROOFS.includes(before) ? "      - name: " : "    name: ";
    const needle = `${prefix}${before}`;
    assert.ok(workflow.includes(needle));
    assert.notDeepEqual(validatePrCheckPolicy(workflow.replace(needle, `${prefix}${after}`)), [], before);
  }
  // Mutate every matrix label individually, including repeated native labels.
  for (const match of workflow.matchAll(/^            label: (.+)$/gm)) {
    const changed = workflow.slice(0, match.index) + match[0].replace(match[1], "renamed-label") + workflow.slice(match.index + match[0].length);
    assert.notDeepEqual(validatePrCheckPolicy(changed), [], match[1]);
  }
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
    const c = exec(["-C", source, "commit-tree", tree, "-p", b], "retry\n");
    const d = exec(["-C", source, "commit-tree", tree, "-p", c], "later\n");
    const bin = join(dir, "bin"); mkdirSync(bin);
    const script = (name, code) => writeFileSync(join(bin, name), `#!${process.execPath}\n${code}`, { mode: 0o755 });
    script("ssh-keyscan", 'console.log("github.com ssh-ed25519 fixture");');
    script("ssh-keygen", 'console.log("256 SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU github.com");');
    script("git", `
      const {spawnSync}=require('node:child_process');
      if(process.env.SOURCE_DEPLOY_KEY || process.env.GH_TOKEN || process.env.GITHUB_TOKEN) process.exit(42);
      const args=process.argv.slice(2).map(a=>a==='git@github.com:Subunit-UG/scai-app.git'?${JSON.stringify(source)}:a);
      if(args.includes('checkout')) process.exit(43);
      if(args.includes('fetch')) require('node:fs').appendFileSync(${JSON.stringify(join(dir, "fetches.jsonl"))},JSON.stringify(args)+'\\n');
      const r=spawnSync(${JSON.stringify(git)},args,{encoding:'utf8'});
      process.stdout.write(r.stdout||''); process.stderr.write(r.stderr||''); process.exit(r.status??1);
    `);
    const env = { ...process.env, RUNNER_TEMP: dir, PATH: `${bin}:${process.env.PATH}`, SOURCE_DEPLOY_KEY: "fixture-key", GH_TOKEN: "fixture-token", GITHUB_TOKEN: "fixture-token" };
    const reader = privateTreeReader(env);
    try {
      assert.equal(reader.treeFor(a), tree);
      reader.prefetch([b, c, d, b]);
      for (const sha of [a, b, c, d]) assert.equal(reader.treeFor(sha), tree);
      const fetches = readFileSync(join(dir, "fetches.jsonl"), "utf8").trim().split("\n").map(JSON.parse);
      assert.equal(fetches.length, 2, "one source fetch plus exactly one batch for N candidate SHAs");
      assert.deepEqual(fetches[1].slice(-3), [b, c, d]);
      assert.throws(() => reader.treeFor("a".repeat(40)), /fetch limit exceeded/);
      assert.equal(readFileSync(join(dir, "fetches.jsonl"), "utf8").trim().split("\n").length, 2);
    }
    finally { reader.close(); }
    assert.ok(!readdirSync(dir).some((name) => name.startsWith("scai-pr-check-")));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("tree reader enforces its time and batch-size budgets without network access", () => {
  const dir = mkdtempSync(join(tmpdir(), "pr-tree-limits-"));
  const env = { RUNNER_TEMP: dir, SOURCE_DEPLOY_KEY: "fixture-key" };
  try {
    const oversized = privateTreeReader(env);
    try {
      assert.throws(() => oversized.prefetch(Array.from({ length: 1001 }, (_, i) => i.toString(16).padStart(40, "0"))), /batch exceeds 1000/);
      assert.throws(() => oversized.prefetch(["--help"]), /Invalid tree request/);
    } finally { oversized.close(); }
    let elapsed = 0;
    const timeouts = [];
    const timed = privateTreeReader(env, { clock: () => elapsed, runCommand: (program, args, options) => {
      timeouts.push(options.timeout);
      if (program === "ssh-keyscan") { elapsed += 50000; return "github.com ssh-ed25519 fixture"; }
      if (program === "ssh-keygen") { elapsed += 50000; return "256 SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU github.com"; }
      elapsed += 20000;
      return "";
    } });
    try { assert.throws(() => timed.treeFor(GREEN), /120-second budget/); }
    finally { timed.close(); }
    assert.deepEqual(timeouts, [60000, 60000, 20000]);
    assert.equal(readdirSync(dir).length, 0, "temporary credentials removed on failure");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("tree reader removes credentials and signal listeners on cancellation", () => {
  for (const [signal, code] of [["SIGINT", 130], ["SIGTERM", 143], ["SIGHUP", 129]]) {
    const dir = mkdtempSync(join(tmpdir(), "pr-tree-signal-"));
    const signals = new EventEmitter();
    const exits = [];
    const reader = privateTreeReader({ RUNNER_TEMP: dir, SOURCE_DEPLOY_KEY: "fixture-key" }, {
      signals, exit: (value) => exits.push(value),
      runCommand: (program, args) => program === "ssh-keyscan" ? "github.com ssh-ed25519 fixture"
        : program === "ssh-keygen" ? "256 SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU github.com"
        : args.at(-1) === `${GREEN}^{commit}` ? GREEN : "a".repeat(40),
    });
    try {
      reader.treeFor(GREEN);
      assert.equal(readdirSync(dir).length, 1);
      signals.emit(signal);
      assert.deepEqual(exits, [code]);
      assert.equal(readdirSync(dir).length, 0);
      for (const name of ["SIGINT", "SIGTERM", "SIGHUP"]) assert.equal(signals.listenerCount(name), 0);
    } finally { reader.close(); rmSync(dir, { recursive: true, force: true }); }
  }
});

test("real signal cancellation removes the temporary key before process exit", { timeout: 10000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "pr-tree-real-signal-"));
  const child = spawn(process.execPath, ["--input-type=module", "-e", `
    import { privateTreeReader } from ${JSON.stringify(new URL("./require-pr-check.mjs", import.meta.url).href)};
    const sha = ${JSON.stringify(GREEN)};
    const reader = privateTreeReader({ RUNNER_TEMP: ${JSON.stringify(dir)}, SOURCE_DEPLOY_KEY: "fixture-key" }, {
      runCommand: (program, args) => program === "ssh-keyscan" ? "github.com ssh-ed25519 fixture"
        : program === "ssh-keygen" ? "256 SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU github.com"
        : args.at(-1) === sha + "^{commit}" ? sha : "a".repeat(40),
    });
    reader.treeFor(sha);
    console.log("ready");
    setInterval(() => {}, 1000);
  `], { stdio: ["ignore", "pipe", "pipe"] });
  try {
    const [data] = await once(child.stdout, "data");
    assert.equal(data.toString().trim(), "ready");
    assert.equal(readdirSync(dir).length, 1);
    const exited = once(child, "exit");
    child.kill("SIGTERM");
    const [code, signal] = await exited;
    assert.equal(code, 143);
    assert.equal(signal, null);
    assert.equal(readdirSync(dir).length, 0);
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    rmSync(dir, { recursive: true, force: true });
  }
});
