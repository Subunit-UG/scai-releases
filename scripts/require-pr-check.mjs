#!/usr/bin/env node
// A successful run belongs to the public workflow repository. Its title binds
// the private source; its head_sha does not. Squash merges must match by tree.
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const SHA = /^[0-9a-f]{40}$/;
const TITLE = /^SCAI PR · ([0-9a-f]{40}) · ([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/;
const REPO = "Subunit-UG/scai-releases";
const WORKFLOW = ".github/workflows/pr-check.yml";
const PAGE_SIZE = 100;
const MAX_PAGES = 10;
const VERIFICATION_BUDGET_MS = 240000;
// Expired evidence requires a fresh PR check, never an unbounded API scan.
export const LOOKBACK_DAYS = 30;
const MAX_TREE_FETCHES = 16;
const TREE_BUDGET_MS = 120000;
export const REQUIRED_JOBS = [
  "Exakten Source-Prüfauftrag ohne private Schlüssel validieren",
  "tsc + vite + cargo test",
  "SCAI + Trace nativ kompilieren (macos-arm64)",
  "SCAI + Trace nativ kompilieren (windows-x64)",
];
export const REQUIRED_PROOFS = [
  "Host-Restore explizit mit WebKit beweisen",
  "Meet-Plugin visuell und interaktiv beweisen",
];
export const OPTIONAL_TRACE = ["linux-core", "macos-arm64", "macos-x64", "windows-x64"]
  .map((label) => `Trace Standalone prüfen (${label})`);
export const SKIPPED_TRACE = "Trace Standalone prüfen (${{ matrix.label }})";
const fail = (message) => { throw new Error(message); };
const positive = (n) => Number.isSafeInteger(n) && n > 0;
const success = (value) => value?.status === "completed" && value.conclusion === "success";

export function sourceFromRun(run, workflowId) {
  if (run?.workflow_id !== workflowId || run.path !== WORKFLOW
      || run.event !== "workflow_dispatch" || run.head_branch !== "main"
      || run.repository?.full_name !== REPO || run.head_repository?.full_name !== REPO
      || !positive(run.id) || !positive(run.run_attempt) || !SHA.test(run.head_sha)) return null;
  return TITLE.exec(run.display_title ?? "")?.[1] ?? null;
}

// Read all pages or fail. Never accept a partial result or silently truncate it.
async function pages(api, path, field, firstPage) {
  const values = [];
  const seen = new Set();
  let total;
  for (let page = 1; page <= MAX_PAGES; page++) {
    const data = page === 1 && firstPage ? firstPage
      : await api(`${path}${path.includes("?") ? "&" : "?"}per_page=${PAGE_SIZE}&page=${page}`);
    if (!Number.isSafeInteger(data?.total_count) || data.total_count < 0
        || !Array.isArray(data[field]) || data[field].length > PAGE_SIZE) fail("Invalid paginated Actions response");
    total ??= data.total_count;
    if (total !== data.total_count || total > PAGE_SIZE * MAX_PAGES) fail("Actions pagination changed or exceeds the bounded search");
    for (const item of data[field]) {
      if (!positive(item?.id) || seen.has(item.id)) fail("Duplicate or invalid Actions identity");
      seen.add(item.id);
      values.push(item);
    }
    if (values.length === total) return values;
    if (values.length > total || data[field].length < PAGE_SIZE) fail("Incomplete Actions pagination");
  }
  fail("Actions pagination exhausted");
}

// The Actions search cap is per query, not a limit on valid release evidence.
// Yield complete windows newest first; stop consuming after evidence is found.
// Fully paginate disjoint daily windows; subdivide saturated windows down to
// seconds. Even exactly 1000 may be a truncated response, so split it too.
async function* runWindows(api, workflowId, since, through, singleWindow = false) {
  const seen = new Set();
  const window = async function* (start, end) {
    const range = `${new Date(start * 1000).toISOString()}..${new Date(end * 1000).toISOString()}`;
    const path = `repos/${REPO}/actions/workflows/${workflowId}/runs?event=workflow_dispatch&branch=main&created=${encodeURIComponent(range)}`;
    const first = await api(`${path}&per_page=${PAGE_SIZE}&page=1`);
    if (!Number.isSafeInteger(first?.total_count) || first.total_count < 0
        || !Array.isArray(first.workflow_runs) || first.workflow_runs.length > PAGE_SIZE) fail("Invalid paginated Actions response");
    if (first.total_count >= PAGE_SIZE * MAX_PAGES) {
      if (start === end) fail("PR-check search window saturated at one second; retry after Actions activity settles or contact release maintainers");
      const middle = Math.floor((start + end) / 2);
      yield* window(middle + 1, end);
      yield* window(start, middle);
      return;
    }
    const runs = await pages(api, path, "workflow_runs", first);
    for (const run of runs) {
      if (seen.has(run.id)) fail("Duplicate Actions identity across search windows");
      seen.add(run.id);
    }
    yield runs;
  };
  const lower = Math.floor(since / 1000);
  if (singleWindow) {
    const runs = [];
    for await (const batch of window(lower, Math.floor(through / 1000))) runs.push(...batch);
    yield runs;
    return;
  }
  for (let end = Math.floor(through / 1000); end >= lower;) {
    const start = Math.max(lower, end - 86400 + 1);
    yield* window(start, end);
    end = start - 1;
  }
}

export function requireJobs(jobs, run) {
  const names = new Map();
  for (const job of jobs) {
    if (names.has(job.name) || job.run_id !== run.id || job.run_attempt !== run.run_attempt
        || job.head_sha !== run.head_sha) fail("Ambiguous or stale PR-check jobs");
    names.set(job.name, job);
    if (job.name === SKIPPED_TRACE && job.conclusion === "skipped" && job.status === "completed") continue;
    if (![...REQUIRED_JOBS, ...OPTIONAL_TRACE].includes(job.name) || !success(job)) fail("PR-check job is missing, skipped or unsuccessful");
  }
  for (const name of REQUIRED_JOBS) {
    const job = names.get(name);
    if (!success(job) || !Array.isArray(job.steps) || job.steps.length === 0) fail("Required PR-check job did not execute successfully");
    if (job.steps.some((step) => step.status !== "completed" || !["success", "skipped"].includes(step.conclusion))) fail("Unsuccessful PR-check step");
  }
  const optional = OPTIONAL_TRACE.filter((name) => names.has(name));
  if ((names.has(SKIPPED_TRACE) && optional.length) || (!names.has(SKIPPED_TRACE) && optional.length !== OPTIONAL_TRACE.length)) fail("Incomplete optional Trace matrix");
  const steps = names.get("tsc + vite + cargo test").steps;
  for (const name of REQUIRED_PROOFS) {
    const found = steps.filter((step) => step.name === name);
    if (found.length !== 1 || !success(found[0])) fail("Required browser proof did not execute successfully");
  }
}

export async function requirePrCheck({ api, sourceSha, treeFor, prefetchTrees, now = new Date(), clock = Date.now }) {
  if (!SHA.test(sourceSha ?? "")) fail("Exact lowercase source SHA required");
  const started = clock();
  const budget = () => {
    const remaining = VERIFICATION_BUDGET_MS - (clock() - started);
    if (remaining <= 0) fail("PR-check verification exceeded the 240-second resource budget; retry after Actions activity settles or contact release maintainers");
    return remaining;
  };
  const request = async (path) => {
    const value = await api(path, { timeout: Math.min(60000, budget()) });
    budget();
    return value;
  };
  const workflow = await request(`repos/${REPO}/actions/workflows/pr-check.yml`);
  if (!positive(workflow?.id) || workflow.path !== WORKFLOW || workflow.state !== "active") fail("Invalid PR-check workflow identity");
  const since = now.getTime() - LOOKBACK_DAYS * 86400000;
  const trees = new Map();
  let sourceTree;
  const currentTime = () => now.getTime() + (clock() - started);
  const select = async (lower, through, singleWindow = false, selected) => {
    budget();
    let completed = false;
    const pending = new Map();
    const scan = async (path) => {
      const data = await request(path);
      for (const candidate of Array.isArray(data?.workflow_runs) ? data.workflow_runs : []) {
        if (selected && sourceFromRun(candidate, workflow.id)
            && ["queued", "in_progress", "waiting", "pending"].includes(candidate.status)
            && Date.parse(candidate.created_at) >= lower && Date.parse(candidate.created_at) <= through
            && (Date.parse(candidate.created_at) > Date.parse(selected.created_at)
              || (candidate.created_at === selected.created_at && candidate.id > selected.id))) {
          if (!pending.has(candidate.id)) pending.set(candidate.id, structuredClone(candidate));
        }
      }
      return data;
    };
    for await (const runs of runWindows(selected ? scan : request, workflow.id, lower, through, singleWindow)) {
      // The final range is fully enumerated before any observed pending run is
      // re-read. Earlier pages (including saturated parent windows) may be stale.
      if (selected) {
        const shas = [...new Set([...pending.values()].map((item) => sourceFromRun(item, workflow.id)))]
          .filter((sha) => !trees.has(sha));
        if (shas.length) {
          if (typeof prefetchTrees !== "function") fail("Batched tree reader required");
          await prefetchTrees(shas, { budget });
        }
        for (const observed of pending.values()) {
          const sha = sourceFromRun(observed, workflow.id);
          const tree = trees.has(sha) ? trees.get(sha) : await treeFor(sha, { budget });
          if (!SHA.test(tree ?? "")) fail("Invalid checked tree");
          trees.set(sha, tree);
          if (tree !== sourceTree) continue;
          const refreshed = await request(`repos/${REPO}/actions/runs/${observed.id}`);
          if (sourceFromRun(refreshed, workflow.id) !== sha || refreshed.id !== observed.id
              || refreshed.run_attempt !== observed.run_attempt || refreshed.head_sha !== observed.head_sha
              || refreshed.created_at !== observed.created_at) fail("PR-check pending run changed during verification");
          const index = runs.findIndex((item) => item.id === refreshed.id);
          if (index >= 0) runs[index] = refreshed;
          else runs.push(refreshed);
        }
      }
      // Only completed outcomes participate. A pending run is not evidence; a
      // retry of the selected run is still rejected by the snapshot checks below.
      const candidates = runs.filter((run) => sourceFromRun(run, workflow.id) && run.status === "completed"
        && Number.isFinite(Date.parse(run.created_at)) && Date.parse(run.created_at) >= lower
        && Date.parse(run.created_at) <= through)
        .sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at) || b.id - a.id);
      if (candidates.length === 0) continue;
      completed = true;
      if (!sourceTree) {
        sourceTree = await treeFor(sourceSha, { budget });
        if (!SHA.test(sourceTree ?? "")) fail("Invalid source tree");
        trees.set(sourceSha, sourceTree);
      }
      // An exact SHA already proves tree equality and bounds the search: older
      // runs cannot win. Newer non-exact SHAs must still be checked, even if red.
      const exact = candidates.findIndex((run) => sourceFromRun(run, workflow.id) === sourceSha);
      const relevant = exact < 0 ? candidates : candidates.slice(0, exact + 1);
      const otherShas = [...new Set(relevant.map((run) => sourceFromRun(run, workflow.id)))]
        .filter((sha) => !trees.has(sha));
      if (otherShas.length) {
        if (typeof prefetchTrees !== "function") fail("Batched tree reader required");
        await prefetchTrees(otherShas, { budget });
      }
      for (const run of relevant) {
        const checkedSha = sourceFromRun(run, workflow.id);
        const checkedTree = trees.has(checkedSha) ? trees.get(checkedSha) : await treeFor(checkedSha, { budget });
        if (!SHA.test(checkedTree ?? "")) fail("Invalid checked tree");
        trees.set(checkedSha, checkedTree);
        if (checkedTree === sourceTree) {
          budget();
          return { run, checkedSha };
        }
      }
    }
    if (!completed) fail("No completed PR check in the bounded search");
    fail("No tree-equivalent completed PR check");
  };
  let { run, checkedSha } = await select(since, currentTime());
  if (!success(run)) fail("Latest tree-equivalent PR check is unsuccessful");
  const fresh = await request(`repos/${REPO}/actions/runs/${run.id}`);
  if (sourceFromRun(fresh, workflow.id) !== checkedSha || !success(fresh)
      || fresh.id !== run.id || fresh.run_attempt !== run.run_attempt || fresh.head_sha !== run.head_sha) fail("PR-check run changed");
  const jobs = await pages(request, `repos/${REPO}/actions/runs/${run.id}/attempts/${run.run_attempt}/jobs`, "jobs");
  requireJobs(jobs, fresh);
  // One fresh, fully paginated range is the last enumeration. The moving
  // upper bound includes runs created while the historical search was active.
  const latest = await select(Date.parse(run.created_at), currentTime(), true, run);
  if (!success(latest.run)) fail("Latest tree-equivalent PR check is unsuccessful");
  if (latest.run.id === run.id && (latest.checkedSha !== checkedSha
      || latest.run.run_attempt !== run.run_attempt || latest.run.head_sha !== run.head_sha
      || latest.run.created_at !== run.created_at)) fail("PR-check candidate selection changed during verification");
  if (latest.run.id !== run.id && !(Date.parse(latest.run.created_at) > Date.parse(run.created_at)
      || (latest.run.created_at === run.created_at && latest.run.id > run.id))) fail("PR-check candidate selection changed during verification");
  // A newer successful run may replace the selection once. Verify its own
  // attempt and jobs; never enumerate again or fall back to older evidence.
  ({ run, checkedSha } = latest);
  const final = await request(`repos/${REPO}/actions/runs/${run.id}`);
  if (sourceFromRun(final, workflow.id) !== checkedSha || !success(final)
      || final.id !== run.id || final.run_attempt !== run.run_attempt || final.head_sha !== run.head_sha) fail("PR-check run changed during verification");
  const finalJobs = await pages(request, `repos/${REPO}/actions/runs/${run.id}/attempts/${run.run_attempt}/jobs`, "jobs");
  requireJobs(finalJobs, final);
  const confirmed = await request(`repos/${REPO}/actions/runs/${run.id}`);
  if (sourceFromRun(confirmed, workflow.id) !== checkedSha || !success(confirmed)
      || confirmed.id !== run.id || confirmed.run_attempt !== run.run_attempt || confirmed.head_sha !== run.head_sha) fail("PR-check run changed during verification");
  return { runId: run.id, attempt: run.run_attempt, checkedSha, sourceSha, tree: sourceTree };
}

// No transport output is public: even errors may contain private object paths.
function command(program, args, options = {}) {
  const result = spawnSync(program, args, { encoding: "utf8", timeout: 60000, maxBuffer: 8 * 1024 * 1024, ...options });
  if (result.error?.code === "ETIMEDOUT") fail("PR-check verification transport timed out");
  if (result.error || result.status !== 0) fail("PR-check verification transport failed");
  return result.stdout.trim();
}

export function privateTreeReader(env, { runCommand = command, clock = Date.now, signals = process, exit = (code) => process.exit(code) } = {}) {
  let directory;
  let childEnv;
  let deadline;
  let fetches = 0;
  const cache = new Map();
  const handlers = new Map();
  const close = () => {
    if (directory) rmSync(directory, { recursive: true, force: true });
    for (const [signal, handler] of handlers) signals.removeListener(signal, handler);
    handlers.clear();
  };
  const execute = (program, args, budget) => {
    deadline ??= clock() + TREE_BUDGET_MS;
    const remaining = deadline - clock();
    if (remaining <= 0) fail("PR-check tree verification exceeded the 120-second budget");
    const result = runCommand(program, args, { env: childEnv, timeout: Math.min(60000, remaining, budget()) });
    budget();
    if (clock() >= deadline) fail("PR-check tree verification exceeded the 120-second budget");
    return result;
  };
  const prefetch = (shas, { budget = () => Infinity } = {}) => {
    if (!Array.isArray(shas) || shas.some((sha) => !SHA.test(sha))) fail("Invalid tree request");
    const missing = [...new Set(shas)].filter((sha) => !cache.has(sha));
    if (!missing.length) return;
    if (fetches >= MAX_TREE_FETCHES) fail("PR-check tree fetch limit exceeded (maximum 16 batches); retry after Actions activity settles or contact release maintainers");
    if (!directory) {
      if (!env.SOURCE_DEPLOY_KEY) fail("Read-only source deploy key is required");
      const base = env.PR_CHECK_TEMP || env.RUNNER_TEMP || tmpdir();
      if (env.PR_CHECK_TEMP) mkdirSync(base, { recursive: true, mode: 0o700 });
      directory = mkdtempSync(join(base, "scai-pr-check-"));
      for (const [signal, code] of [["SIGINT", 130], ["SIGTERM", 143], ["SIGHUP", 129]]) {
        const handler = () => { try { close(); } finally { exit(code); } };
        handlers.set(signal, handler);
        signals.once(signal, handler);
      }
      const key = join(directory, "key");
      const hosts = join(directory, "known_hosts");
      writeFileSync(key, `${env.SOURCE_DEPLOY_KEY}\n`, { mode: 0o600 });
      childEnv = { ...env };
      delete childEnv.SOURCE_DEPLOY_KEY;
      delete childEnv.GH_TOKEN;
      delete childEnv.GITHUB_TOKEN;
      const hostKey = execute("ssh-keyscan", ["-t", "ed25519", "github.com"], budget)
        .split("\n").filter((line) => line && !line.startsWith("#"));
      if (hostKey.length !== 1) fail("Invalid GitHub host key");
      writeFileSync(hosts, `${hostKey[0]}\n`, { mode: 0o600 });
      const fingerprint = execute("ssh-keygen", ["-lf", hosts, "-E", "sha256"], budget).split(/\s+/)[1];
      if (fingerprint !== "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU") fail("GitHub host key pin mismatch");
      const quote = (value) => `'${value.replaceAll("'", "'\\''")}'`;
      childEnv.GIT_SSH_COMMAND = `ssh -i ${quote(key)} -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o ${quote(`UserKnownHostsFile=${hosts}`)}`;
      childEnv.GIT_TERMINAL_PROMPT = "0";
      execute("git", ["init", "--bare", join(directory, "source.git")], budget);
    }
    const git = (args) => execute("git", ["-C", join(directory, "source.git"), ...args], budget);
    // Fetch commit/tree objects only; never check out or execute private code.
    for (let offset = 0; offset < missing.length; offset += PAGE_SIZE * MAX_PAGES) {
      if (fetches >= MAX_TREE_FETCHES) fail("PR-check tree fetch limit exceeded (maximum 16 batches); retry after Actions activity settles or contact release maintainers");
      const batch = missing.slice(offset, offset + PAGE_SIZE * MAX_PAGES);
      fetches++;
      git(["fetch", "--quiet", "--no-tags", "--depth=1", "--filter=blob:none", "git@github.com:Subunit-UG/scai-app.git", ...batch]);
      for (const sha of batch) {
        if (git(["rev-parse", `${sha}^{commit}`]) !== sha) fail("Source commit drift");
        const tree = git(["rev-parse", `${sha}^{tree}`]);
        if (!SHA.test(tree)) fail("Invalid Git tree");
        cache.set(sha, tree);
      }
    }
  };
  return {
    prefetch,
    treeFor(sha, options) {
      prefetch([sha], options);
      return cache.get(sha);
    },
    close,
  };
}

export async function main(env = process.env) {
  if (env.GITHUB_REPOSITORY !== REPO || env.GITHUB_REF !== "refs/heads/main") fail("PR-check guard requires the main workflow branch");
  if (!env.GH_TOKEN) fail("Actions read token required");
  const childEnv = { ...env };
  delete childEnv.SOURCE_DEPLOY_KEY;
  const api = async (path, options) => {
    const response = command("gh", ["api", "--method", "GET", path], { env: childEnv, ...options });
    try { return JSON.parse(response); } catch { fail("Invalid Actions JSON"); }
  };
  const reader = privateTreeReader(env);
  try {
    const proof = await requirePrCheck({ api, sourceSha: env.SOURCE_SHA,
      treeFor: (sha, options) => reader.treeFor(sha, options), prefetchTrees: (shas, options) => reader.prefetch(shas, options) });
    if (env.GITHUB_OUTPUT) appendFileSync(env.GITHUB_OUTPUT, `pr_check_run_id=${proof.runId}\npr_check_tree=${proof.tree}\n`);
    console.log(`PASS required-pr-check run=${proof.runId} attempt=${proof.attempt} source=${proof.sourceSha} checked=${proof.checkedSha} tree=${proof.tree}`);
    return proof;
  } finally { reader.close(); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error) => { console.error(`::error::${error.message}`); process.exitCode = 1; });
}
