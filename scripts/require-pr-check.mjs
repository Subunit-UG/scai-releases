#!/usr/bin/env node
// A successful run belongs to the public workflow repository. Its title binds
// the private source; its head_sha does not. Squash merges must match by tree.
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync, appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const SHA = /^[0-9a-f]{40}$/;
const TITLE = /^SCAI PR · ([0-9a-f]{40}) · ([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/;
const REPO = "Subunit-UG/scai-releases";
const WORKFLOW = ".github/workflows/pr-check.yml";
const PAGE_SIZE = 100;
const MAX_PAGES = 10;
// Expired evidence requires a fresh PR check, never an unbounded API scan.
export const LOOKBACK_DAYS = 30;
const MAX_TREE_FETCHES = 2;
const TREE_BUDGET_MS = 120000;
export const REQUIRED_JOBS = [
  "Exakten Source-Prüfauftrag ohne private Schlüssel validieren",
  "tsc + vite + cargo test",
  "SCAI + Trace nativ kompilieren (macos-arm64)",
  "SCAI + Trace nativ kompilieren (windows-x64)",
];
const REQUIRED_PROOFS = [
  "Host-Restore explizit mit WebKit beweisen",
  "Meet-Plugin visuell und interaktiv beweisen",
];
const OPTIONAL_TRACE = ["linux-core", "macos-arm64", "macos-x64", "windows-x64"]
  .map((label) => `Trace Standalone prüfen (${label})`);
const SKIPPED_TRACE = "Trace Standalone prüfen (${{ matrix.label }})";
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
async function pages(api, path, field) {
  const values = [];
  const seen = new Set();
  let total;
  for (let page = 1; page <= MAX_PAGES; page++) {
    const data = await api(`${path}${path.includes("?") ? "&" : "?"}per_page=${PAGE_SIZE}&page=${page}`);
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

export async function requirePrCheck({ api, sourceSha, treeFor, prefetchTrees, now = new Date() }) {
  if (!SHA.test(sourceSha ?? "")) fail("Exact lowercase source SHA required");
  const workflow = await api(`repos/${REPO}/actions/workflows/pr-check.yml`);
  if (!positive(workflow?.id) || workflow.path !== WORKFLOW || workflow.state !== "active") fail("Invalid PR-check workflow identity");
  const since = new Date(now.getTime() - LOOKBACK_DAYS * 86400000).toISOString();
  const runs = await pages(api,
    `repos/${REPO}/actions/workflows/${workflow.id}/runs?event=workflow_dispatch&branch=main&created=${encodeURIComponent(`>=${since}`)}`,
    "workflow_runs");
  // Only completed outcomes participate. A pending run is not evidence; a
  // retry of the selected run is still rejected by the snapshot checks below.
  const candidates = runs.filter((run) => sourceFromRun(run, workflow.id) && run.status === "completed"
    && Number.isFinite(Date.parse(run.created_at)) && Date.parse(run.created_at) >= Date.parse(since)
    && Date.parse(run.created_at) <= now.getTime())
    .sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at) || b.id - a.id);
  if (candidates.length === 0) fail("No completed PR check in the bounded search");
  const sourceTree = await treeFor(sourceSha);
  if (!SHA.test(sourceTree ?? "")) fail("Invalid source tree");
  // An exact SHA already proves tree equality and bounds the search: older
  // runs cannot win. Newer non-exact SHAs must still be checked, even if red.
  const exact = candidates.findIndex((run) => sourceFromRun(run, workflow.id) === sourceSha);
  const relevant = exact < 0 ? candidates : candidates.slice(0, exact + 1);
  const otherShas = [...new Set(relevant.map((run) => sourceFromRun(run, workflow.id)))]
    .filter((sha) => sha !== sourceSha);
  if (otherShas.length) {
    if (typeof prefetchTrees !== "function") fail("Batched tree reader required");
    await prefetchTrees(otherShas);
  }
  const matching = [];
  for (const run of relevant) {
    const checkedSha = sourceFromRun(run, workflow.id);
    const checkedTree = checkedSha === sourceSha ? sourceTree : await treeFor(checkedSha);
    if (!SHA.test(checkedTree ?? "")) fail("Invalid checked tree");
    if (checkedTree === sourceTree) matching.push({ run, checkedSha });
  }
  if (matching.length === 0) fail("No tree-equivalent completed PR check");
  const { run, checkedSha } = matching[0];
  if (!success(run)) fail("Latest tree-equivalent PR check is unsuccessful");
  const fresh = await api(`repos/${REPO}/actions/runs/${run.id}`);
  if (sourceFromRun(fresh, workflow.id) !== checkedSha || !success(fresh)
      || fresh.id !== run.id || fresh.run_attempt !== run.run_attempt || fresh.head_sha !== run.head_sha) fail("PR-check run changed");
  const jobs = await pages(api, `repos/${REPO}/actions/runs/${run.id}/attempts/${run.run_attempt}/jobs`, "jobs");
  requireJobs(jobs, fresh);
  // A concurrent rerun invalidates the snapshot instead of mixing attempts.
  const final = await api(`repos/${REPO}/actions/runs/${run.id}`);
  if (sourceFromRun(final, workflow.id) !== checkedSha || !success(final)
      || final.id !== run.id || final.run_attempt !== run.run_attempt || final.head_sha !== run.head_sha) fail("PR-check run changed during verification");
  return { runId: run.id, attempt: run.run_attempt, checkedSha, sourceSha, tree: sourceTree };
}

// No transport output is public: even errors may contain private object paths.
function command(program, args, options = {}) {
  const result = spawnSync(program, args, { encoding: "utf8", timeout: 60000, maxBuffer: 8 * 1024 * 1024, ...options });
  if (result.error?.code === "ETIMEDOUT") fail("PR-check verification transport timed out");
  if (result.error || result.status !== 0) fail("PR-check verification transport failed");
  return result.stdout.trim();
}

export function privateTreeReader(env, { runCommand = command, clock = Date.now } = {}) {
  let directory;
  let childEnv;
  let deadline;
  let fetches = 0;
  const cache = new Map();
  const execute = (program, args) => {
    deadline ??= clock() + TREE_BUDGET_MS;
    const remaining = deadline - clock();
    if (remaining <= 0) fail("PR-check tree verification exceeded the 120-second budget");
    const result = runCommand(program, args, { env: childEnv, timeout: Math.min(60000, remaining) });
    if (clock() >= deadline) fail("PR-check tree verification exceeded the 120-second budget");
    return result;
  };
  const prefetch = (shas) => {
    if (!Array.isArray(shas) || shas.some((sha) => !SHA.test(sha))) fail("Invalid tree request");
    const missing = [...new Set(shas)].filter((sha) => !cache.has(sha));
    if (!missing.length) return;
    if (missing.length > PAGE_SIZE * MAX_PAGES) fail("PR-check tree batch exceeds 1000 SHAs");
    if (fetches >= MAX_TREE_FETCHES) fail("PR-check tree fetch limit exceeded (maximum 2 batches)");
    if (!directory) {
      if (!env.SOURCE_DEPLOY_KEY) fail("Read-only source deploy key is required");
      directory = mkdtempSync(join(env.RUNNER_TEMP || tmpdir(), "scai-pr-check-"));
      const key = join(directory, "key");
      const hosts = join(directory, "known_hosts");
      writeFileSync(key, `${env.SOURCE_DEPLOY_KEY}\n`, { mode: 0o600 });
      childEnv = { ...env };
      delete childEnv.SOURCE_DEPLOY_KEY;
      delete childEnv.GH_TOKEN;
      delete childEnv.GITHUB_TOKEN;
      const hostKey = execute("ssh-keyscan", ["-t", "ed25519", "github.com"])
        .split("\n").filter((line) => line && !line.startsWith("#"));
      if (hostKey.length !== 1) fail("Invalid GitHub host key");
      writeFileSync(hosts, `${hostKey[0]}\n`, { mode: 0o600 });
      const fingerprint = execute("ssh-keygen", ["-lf", hosts, "-E", "sha256"]).split(/\s+/)[1];
      if (fingerprint !== "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU") fail("GitHub host key pin mismatch");
      const quote = (value) => `'${value.replaceAll("'", "'\\''")}'`;
      childEnv.GIT_SSH_COMMAND = `ssh -i ${quote(key)} -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o ${quote(`UserKnownHostsFile=${hosts}`)}`;
      childEnv.GIT_TERMINAL_PROMPT = "0";
      execute("git", ["init", "--bare", join(directory, "source.git")]);
    }
    const git = (args) => execute("git", ["-C", join(directory, "source.git"), ...args]);
    // Fetch commit/tree objects only; never check out or execute private code.
    fetches++;
    git(["fetch", "--quiet", "--no-tags", "--depth=1", "--filter=blob:none", "git@github.com:Subunit-UG/scai-app.git", ...missing]);
    for (const sha of missing) {
      if (git(["rev-parse", `${sha}^{commit}`]) !== sha) fail("Source commit drift");
      const tree = git(["rev-parse", `${sha}^{tree}`]);
      if (!SHA.test(tree)) fail("Invalid Git tree");
      cache.set(sha, tree);
    }
  };
  return {
    prefetch,
    treeFor(sha) {
      prefetch([sha]);
      return cache.get(sha);
    },
    close() { if (directory) rmSync(directory, { recursive: true, force: true }); },
  };
}

export async function main(env = process.env) {
  if (env.GITHUB_REPOSITORY !== REPO || env.GITHUB_REF !== "refs/heads/main") fail("PR-check guard requires the main workflow branch");
  if (!env.GH_TOKEN) fail("Actions read token required");
  const childEnv = { ...env };
  delete childEnv.SOURCE_DEPLOY_KEY;
  const api = async (path) => {
    const response = command("gh", ["api", "--method", "GET", path], { env: childEnv });
    try { return JSON.parse(response); } catch { fail("Invalid Actions JSON"); }
  };
  const reader = privateTreeReader(env);
  try {
    const proof = await requirePrCheck({ api, sourceSha: env.SOURCE_SHA,
      treeFor: (sha) => reader.treeFor(sha), prefetchTrees: (shas) => reader.prefetch(shas) });
    if (env.GITHUB_OUTPUT) appendFileSync(env.GITHUB_OUTPUT, `pr_check_run_id=${proof.runId}\npr_check_tree=${proof.tree}\n`);
    console.log(`PASS required-pr-check run=${proof.runId} attempt=${proof.attempt} source=${proof.sourceSha} checked=${proof.checkedSha} tree=${proof.tree}`);
    return proof;
  } finally { reader.close(); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error) => { console.error(`::error::${error.message}`); process.exitCode = 1; });
}
