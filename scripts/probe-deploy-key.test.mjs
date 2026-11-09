// Tests für den Deploy-Key-Wächter (scripts/probe-deploy-key.sh). Netz und GitHub werden durch Attrappen im PATH
// ersetzt; geprüft wird Allowlist, fehlender Schlüssel, Hostschlüssel-Pin, Erfolg/Fehler und dass kein Schlüsselmaterial
// in Ausgabe oder Dateien zurückbleibt.
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PROBE = join(ROOT, "scripts/probe-deploy-key.sh");
const ATTRAPPE = "nur eine attrappe"; // kein Schlüssel, nur zum Nachweis, dass nichts durchsickert
// Gepinnter GitHub-Host-Fingerabdruck (öffentlich) direkt aus dem Skript, damit Test und Skript nie auseinanderlaufen.
const PIN = readFileSync(PROBE, "utf8").match(/github_ed25519_fingerprint="([^"]+)"/)[1];

function run(args, { key = ATTRAPPE, git = 0, fingerprint = PIN, hosts = 1 } = {}) {
  const root = mkdtempSync(join(tmpdir(), "key-probe-test-"));
  const bin = join(root, "bin"), runner = join(root, "runner");
  mkdirSync(bin); mkdirSync(runner);
  const log = join(root, "git.log");
  const fake = (name, body) => { writeFileSync(join(bin, name), `#!/usr/bin/env bash\n${body}\n`); chmodSync(join(bin, name), 0o755); };
  fake("ssh-keyscan", Array.from({ length: hosts }, (_, i) => `echo "github.com ssh-ed25519 AAAA${i}"`).join("\n"));
  fake("ssh-keygen", `echo "256 ${fingerprint} github.com (ED25519)"`);
  fake("git", `printf '%s|%s\\n' "$*" "$GIT_SSH_COMMAND" >> "${log}"; echo "refs/heads/main deadbeef"; exit ${git}`);
  const env = { PATH: `${bin}:${process.env.PATH}`, RUNNER_TEMP: runner, HOME: root };
  if (key !== null) env.SOURCE_DEPLOY_KEY = key;
  const result = spawnSync("bash", [PROBE, ...args], { encoding: "utf8", env });
  const out = { ...result, log: existsSync(log) ? readFileSync(log, "utf8") : "", leftover: readdirSync(runner) };
  rmSync(root, { recursive: true, force: true });
  return out;
}

test("lesbares Repo: PASS, ls-remote auf genau das zugeordnete Repo, keine Refs und kein Schlüssel in der Ausgabe", () => {
  const r = run(["AUTH_SOURCE_DEPLOY_KEY", "Subunit-UG/infra-auth"]);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /^PASS deploy-key AUTH_SOURCE_DEPLOY_KEY → Subunit-UG\/infra-auth lesbar$/m);
  assert.match(r.log, /^ls-remote --heads git@github\.com:Subunit-UG\/infra-auth\.git\|/m);
  assert.match(r.log, /IdentitiesOnly=yes/); assert.match(r.log, /StrictHostKeyChecking=yes/); assert.match(r.log, /BatchMode=yes/);
  assert.doesNotMatch(r.stdout + r.stderr + r.log, /deadbeef|nur eine attrappe/);
  assert.deepEqual(r.leftover, [], "Schlüsselordner wird entfernt");
});

test("nicht lesbares Repo (Schlüssel im Repo entfernt): Exit 1 mit sichtbarem Fehler, Schlüssel trotzdem aufgeräumt", () => {
  const r = run(["SOURCE_DEPLOY_KEY", "Subunit-UG/scai-app"], { git: 128 });
  assert.equal(r.status, 1);
  assert.match(r.stdout, /::error title=Deploy-Key ungültig::SOURCE_DEPLOY_KEY kann Subunit-UG\/scai-app nicht lesen/);
  assert.doesNotMatch(r.stdout + r.stderr, /nur eine attrappe/);
  assert.deepEqual(r.leftover, []);
});

test("fehlender oder leerer Schlüssel: Exit 65, kein Git-Aufruf", () => {
  for (const key of [null, ""]) {
    const r = run(["U1_CHAT_SOURCE_DEPLOY_KEY", "Subunit-UG/infra-u1-chat"], { key });
    assert.equal(r.status, 65); assert.equal(r.log, ""); assert.match(r.stdout, /Deploy-Key fehlt/);
  }
});

test("Allowlist: falsche Paarung, fremdes Repo oder Zusatzargumente → 64, kein Git-Aufruf", () => {
  for (const args of [["AUTH_SOURCE_DEPLOY_KEY", "Subunit-UG/scai-app"], ["AUTH_SOURCE_DEPLOY_KEY", "evil/infra-auth"],
    ["AUTH_SOURCE_DEPLOY_KEY", "Subunit-UG/infra-auth.git --upload-pack=x"], ["AUTH_SOURCE_DEPLOY_KEY"], []]) {
    const r = run(args);
    assert.equal(r.status, 64, JSON.stringify(args)); assert.equal(r.log, "");
  }
});

test("GitHub-Hostschlüssel falsch oder mehrdeutig → 68, kein Git-Aufruf", () => {
  for (const opts of [{ fingerprint: "SHA256:falsch" }, { hosts: 2 }, { hosts: 0 }]) {
    const r = run(["TRACE_SOURCE_DEPLOY_KEY", "Subunit-UG/trace-tauri"], opts);
    assert.equal(r.status, 68, JSON.stringify(opts)); assert.equal(r.log, ""); assert.deepEqual(r.leftover, []);
  }
});

test("Workflow prüft genau die Secrets, die die Checks benutzen, und läuft täglich mit nur lesenden Rechten", () => {
  const wf = readFileSync(join(ROOT, ".github/workflows/deploy-key-probe.yml"), "utf8");
  const used = new Set();
  for (const f of readdirSync(join(ROOT, ".github/workflows"))) {
    if (f === "deploy-key-probe.yml") continue;
    for (const m of readFileSync(join(ROOT, ".github/workflows", f), "utf8").matchAll(/secrets\.([A-Z0-9_]*SOURCE_DEPLOY_KEY)\b/g)) used.add(m[1]);
  }
  const probed = new Set([...wf.matchAll(/SOURCE_DEPLOY_KEY: \$\{\{ secrets\.([A-Z0-9_]*SOURCE_DEPLOY_KEY) \}\}\n        run: bash scripts\/probe-deploy-key\.sh \1 /g)].map(m => m[1]));
  for (const s of used) assert.ok(probed.has(s), `${s} wird in Checks benutzt, aber nicht geprüft`);
  assert.match(wf, /schedule:\s*\n\s*- cron:/);
  assert.match(wf, /permissions:\s*\n\s*contents: read/);
  assert.doesNotMatch(wf, /secrets\s*\[/, "kein dynamischer secrets[...]-Zugriff");
  assert.equal((wf.match(/if: \$\{\{ !cancelled\(\) \}\}/g) ?? []).length, probed.size, "jede Probe läuft auch nach einem Fehlschlag");
});
