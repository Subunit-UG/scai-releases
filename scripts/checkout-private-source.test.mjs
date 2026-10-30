import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const HELPER = join(ROOT, "scripts/checkout-private-source.sh");
const SHA = "a".repeat(40);

function invoke(args, env = {}) {
  const testRoot = mkdtempSync(join(tmpdir(), "scai-private-checkout-test-"));
  const runnerTemp = join(testRoot, "runner-temp");
  const workspace = join(testRoot, "workspace");
  mkdirSync(runnerTemp);
  mkdirSync(workspace);
  const result = spawnSync("bash", [HELPER, ...args], {
    encoding: "utf8",
    env: { ...process.env, GITHUB_WORKSPACE: workspace, RUNNER_TEMP: runnerTemp, ...env },
  });
  return { ...result, runnerTemp, testRoot, workspace };
}

function cleanup(testRoot) {
  rmSync(testRoot, { recursive: true, force: true });
}

for (const platform of ['Linux', 'MINGW64_NT-10.0']) {
  for (const failure of ['success', 'init', 'fetch', 'detach', 'drift', 'TERM', 'KILL', 'keygen']) {
    test(`Credential lifecycle (${platform}, ${failure})`, t => {
      const root = mkdtempSync(join(tmpdir(), 'checkout-lifecycle-'));
      t.after(() => cleanup(root));
      const bin = join(root, 'bin'), runner = join(root, 'runner'), workspace = join(root, 'workspace'), testHome = join(root, 'home');
      for (const path of [bin, runner, workspace, join(testHome, '.ssh')]) mkdirSync(path, { recursive: true });
      const output = join(root, 'env'), githubEnv = join(root, 'github-env');
      writeFileSync(githubEnv, 'UNCHANGED\n');
      const outsideKey = join(root, 'outside-key');
      writeFileSync(outsideKey, 'PRESERVE');
      // The previous Unix helper followed this predictable symlink and left
      // the credential in its target after removing only the symlink.
      symlinkSync(outsideKey, join(runner, 'scai-sonar-tauri-deploy-key'));
      writeMock(bin, 'uname', 'echo "$MOCK_PLATFORM"');
      writeMock(bin, 'cygpath', 'printf "%s\\n" "$2"');
      writeMock(bin, 'ssh-keyscan', "echo 'github.com ssh-ed25519 AAAAPINNED'");
      writeMock(bin, 'ssh-keygen', `
[ "\${SOURCE_DEPLOY_KEY+x}" != x ]
if [ "$MOCK_FAILURE" = keygen ]; then exit 19; fi
echo '256 SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU github.com (ED25519)'`);
      writeMock(bin, 'git', `
[ "\${SOURCE_DEPLOY_KEY+x}" != x ]
case "$1" in
  init)
    if [ "$MOCK_FAILURE" = TERM ]; then kill -TERM "$PPID"; exit 0; fi
    if [ "$MOCK_FAILURE" = KILL ]; then kill -KILL "$PPID"; exit 0; fi
    if [ "$MOCK_FAILURE" = init ]; then exit 20; fi
    mkdir -p "$3/.git" ;;
  -C)
    if [ "$3" = fetch ] || [ "$3" = checkout ]; then
      if [ "$MOCK_FAILURE" = fetch ] && [ "$3" = fetch ]; then exit 21; fi
      if [ "$MOCK_FAILURE" = detach ] && [ "$3" = checkout ]; then exit 22; fi
    fi
    if [ "$3" = rev-parse ]; then
      if [ "$MOCK_FAILURE" = drift ]; then printf '%040d\\n' 1; else echo "$MOCK_SHA"; fi
    fi ;;
esac`);
      const env = { ...process.env, PATH: `${bin}:${process.env.PATH}`, HOME: testHome, RUNNER_TEMP: runner, GITHUB_WORKSPACE: workspace, GITHUB_ENV: githubEnv, GITHUB_OUTPUT: output, SOURCE_DEPLOY_KEY: 'PRIVATE_DEPLOY_KEY_CANARY', MOCK_FAILURE: failure, MOCK_PLATFORM: platform, MOCK_SHA: SHA };
      const result = spawnSync('bash', [HELPER, 'sonar-tauri', 'git@github.com:Subunit-UG/sonar-tauri.git', SHA], { env, encoding: 'utf8', timeout: 10000 });
      if (failure === 'KILL') assert.equal(result.signal, 'SIGKILL');
      else assert.equal(result.status, { success: 0, init: 20, fetch: 21, detach: 22, drift: 67, TERM: 143, keygen: 19 }[failure], result.stdout + result.stderr);
      assert.doesNotMatch(result.stdout + result.stderr, /PRIVATE_DEPLOY_KEY_CANARY|scai-checkout-credentials/);
      const credentialRoot = platform === 'Linux' ? runner : join(testHome, '.ssh');
      const leases = readdirSync(credentialRoot).filter(n => n.startsWith('scai-checkout-credentials.'));
      assert.equal(leases.length, failure === 'KILL' ? 1 : 0);
      if (failure === 'KILL') {
        assert.equal(statSync(join(credentialRoot, leases[0])).mode & 0o777, 0o700);
        assert.equal(statSync(join(credentialRoot, leases[0], 'key')).mode & 0o777, 0o600);
      }
      const swept = spawnSync('bash', [HELPER, '--cleanup-credentials'], { env, encoding: 'utf8' });
      assert.equal(swept.status, 0, swept.stderr);
      assert.deepEqual(readdirSync(credentialRoot).filter(n => n.startsWith('scai-checkout-credentials.')), []);
      assert.equal(readFileSync(githubEnv, 'utf8'), 'UNCHANGED\n');
      assert.equal(readFileSync(outsideKey, 'utf8'), 'PRESERVE');
      assert.equal(existsSync(output), false);
    });
  }
}

test('credential barrier refuses symlink leases and unexpected contents', t => {
  const root = mkdtempSync(join(tmpdir(), 'checkout-sweep-'));
  t.after(() => cleanup(root));
  const testHome = join(root, 'home'); mkdirSync(testHome);
  const outside = join(root, 'outside'); mkdirSync(outside);
  writeFileSync(join(outside, 'key'), 'PRESERVE');
  const lease = join(root, 'scai-checkout-credentials.fixture');
  symlinkSync(outside, lease);
  const run = () => spawnSync('bash', [HELPER, '--cleanup-credentials'], { encoding: 'utf8', env: { ...process.env, HOME: testHome, RUNNER_TEMP: root } });
  assert.notEqual(run().status, 0);
  assert.equal(readFileSync(join(outside, 'key'), 'utf8'), 'PRESERVE');
  rmSync(lease); mkdirSync(lease); writeFileSync(join(lease, 'unexpected'), 'PRESERVE');
  assert.notEqual(run().status, 0);
  assert.equal(readFileSync(join(lease, 'unexpected'), 'utf8'), 'PRESERVE');
});

function writeMock(binDir, name, body) {
  const target = join(binDir, name);
  writeFileSync(target, `#!/usr/bin/env bash\nset -euo pipefail\n${body}\n`);
  chmodSync(target, 0o755);
}

test("repository allowlist, immutable SHA and dedicated key fail closed", () => {
  for (const [args, expectedStatus, expectedMessage] of [
    [["u1-chat", "git@github.com:attacker/source.git", SHA], 64, /not allowlisted/],
    [["u1-chat", "git@github.com:Subunit-UG/infra-u1-chat.git", "main"], 64, /40 lowercase hexadecimal/],
    [["u1-chat", "git@github.com:Subunit-UG/infra-u1-chat.git", SHA], 65, /deploy key is missing/],
    [["subunit-notch", "git@github.com:Subunit-UG/mac-notch.git", SHA], 65, /deploy key is missing/],
    [["subunit-notch", "git@github.com:Subunit-UG/echo-server.git", SHA], 64, /not allowlisted/],
    [["subunit-scai", "git@github.com:Subunit-UG/scai-app.git", SHA], 65, /deploy key is missing/],
    [["subunit-scai", "git@github.com:Subunit-UG/infra-atlas.git", SHA], 64, /not allowlisted/],
  ]) {
    const result = invoke(args);
    assert.equal(result.status, expectedStatus);
    assert.match(result.stdout + result.stderr, expectedMessage);
    cleanup(result.testRoot);
  }
});

// Org-Umzug (TJ 2026-10-30): je Komponente genau der kanonische Subunit-UG-Pfad. Alte
// subunit-ai-Pfade (nur noch per Weiterleitung), fremde Owner und Doppelgänger werden
// vor jedem Schlüssel- oder Netzzugriff abgewiesen.
const CANONICAL_SOURCES = {
  "u1-chat": "Subunit-UG/infra-u1-chat", atlas: "Subunit-UG/infra-atlas", "subunit-auth": "Subunit-UG/infra-auth",
  "subunit-scai": "Subunit-UG/scai-app", echo: "Subunit-UG/echo-server", "subunit-notch": "Subunit-UG/mac-notch",
  "sonar-tauri": "Subunit-UG/sonar-tauri", "bridge-tauri": "Subunit-UG/bridge-tauri", "trace-tauri": "Subunit-UG/trace-tauri",
};
for (const [component, repository] of Object.entries(CANONICAL_SOURCES)) test(`Org-Umzug: ${component} nur über ${repository}`, () => {
  const name = repository.split("/")[1];
  for (const [source, status] of [
    [`git@github.com:${repository}.git`, 65],
    [`git@github.com:subunit-ai/${component}.git`, 64],
    [`git@github.com:subunit-ai/${name}.git`, 64],
    [`git@github.com:attacker/${name}.git`, 64],
    [`git@github.com:Subunit-UG-evil/${name}.git`, 64],
    [`git@github.com:${repository}.git.evil`, 64],
    [`https://github.com/${repository}.git`, 64],
  ]) {
    const result = invoke([component, source, SHA], { SOURCE_DEPLOY_KEY: "" });
    assert.equal(result.status, status, `${component} ${source}: ${result.stdout}${result.stderr}`);
    assert.match(result.stdout + result.stderr, status === 65 ? /deploy key is missing/ : /not allowlisted/);
    cleanup(result.testRoot);
  }
});

test("an untrusted GitHub host key is rejected and credential files are cleaned", () => {
  const testRoot = mkdtempSync(join(tmpdir(), "scai-private-host-test-"));
  const binDir = join(testRoot, "bin");
  const runnerTemp = join(testRoot, "runner-temp");
  const workspace = join(testRoot, "workspace");
  mkdirSync(binDir);
  mkdirSync(runnerTemp);
  mkdirSync(workspace);
  writeMock(binDir, "ssh-keyscan", "printf '%s\\n' 'github.com ssh-ed25519 AAAAUNTRUSTED'");
  writeMock(binDir, "ssh-keygen", "printf '%s\\n' '256 SHA256:WRONG github.com (ED25519)'");

  const secret = "PRIVATE_DEPLOY_KEY_CANARY";
  const result = spawnSync("bash", [HELPER, "u1-chat", "git@github.com:Subunit-UG/infra-u1-chat.git", SHA], {
    encoding: "utf8",
    env: {
      ...process.env,
      GITHUB_WORKSPACE: workspace,
      RUNNER_TEMP: runnerTemp,
      SOURCE_DEPLOY_KEY: secret,
      PATH: `${binDir}:${process.env.PATH}`,
    },
  });

  assert.equal(result.status, 68);
  assert.match(result.stdout + result.stderr, /host verification failed/);
  assert.doesNotMatch(result.stdout + result.stderr, new RegExp(secret));
  assert.equal(existsSync(join(runnerTemp, "scai-u1-chat-deploy-key")), false);
  assert.equal(existsSync(join(runnerTemp, "scai-u1-chat-known-hosts")), false);
  cleanup(testRoot);
});

test("the happy path fetches and detaches the exact SHA without retaining credentials", () => {
  const testRoot = mkdtempSync(join(tmpdir(), "scai-private-success-test-"));
  const binDir = join(testRoot, "bin");
  const runnerTemp = join(testRoot, "runner-temp");
  const workspace = join(testRoot, "workspace");
  const gitLog = join(testRoot, "git-calls.log");
  mkdirSync(binDir);
  mkdirSync(runnerTemp);
  mkdirSync(workspace);
  writeMock(binDir, "ssh-keyscan", "printf '%s\\n' 'github.com ssh-ed25519 AAAAPINNED'");
  writeMock(binDir, "ssh-keygen", "printf '%s\\n' '256 SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU github.com (ED25519)'");
  writeMock(binDir, "git", `
printf '%s\\n' "$*" >> "$MOCK_GIT_LOG"
if [ "\${1:-}" = "init" ]; then
  mkdir -p "\${3:?}/.git"
elif [ "\${1:-}" = "-C" ] && [ "\${3:-}" = "rev-parse" ]; then
  printf '%s\\n' "$MOCK_SOURCE_SHA"
fi
`);

  const secret = "PRIVATE_DEPLOY_KEY_CANARY";
  const result = spawnSync("bash", [HELPER, "u1-chat", "git@github.com:Subunit-UG/infra-u1-chat.git", SHA], {
    encoding: "utf8",
    env: {
      ...process.env,
      GITHUB_WORKSPACE: workspace,
      RUNNER_TEMP: runnerTemp,
      SOURCE_DEPLOY_KEY: secret,
      MOCK_GIT_LOG: gitLog,
      MOCK_SOURCE_SHA: SHA,
      PATH: `${binDir}:${process.env.PATH}`,
    },
  });

  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, new RegExp(`PASS private-checkout-u1-chat \\(source-sha=${SHA}\\)`));
  assert.doesNotMatch(result.stdout + result.stderr, new RegExp(secret));
  const calls = readFileSync(gitLog, "utf8");
  assert.match(calls, new RegExp(`fetch --depth 1 origin ${SHA}`));
  assert.match(calls, new RegExp(`checkout --detach ${SHA}`));
  assert.match(calls, /remote remove origin/);
  assert.equal(existsSync(join(runnerTemp, "scai-u1-chat-deploy-key")), false);
  assert.equal(existsSync(join(runnerTemp, "scai-u1-chat-known-hosts")), false);
  cleanup(testRoot);
});

test("Echo historical fixture fetch cannot replace the candidate checkout", () => {
  const testRoot = mkdtempSync(join(tmpdir(), "scai-private-success-test-"));
  const binDir = join(testRoot, "bin");
  const runnerTemp = join(testRoot, "runner-temp");
  const workspace = join(testRoot, "workspace");
  const gitLog = join(testRoot, "git-calls.log");
  mkdirSync(binDir);
  mkdirSync(runnerTemp);
  mkdirSync(workspace);
  writeMock(binDir, "ssh-keyscan", "printf '%s\\n' 'github.com ssh-ed25519 AAAAPINNED'");
  writeMock(binDir, "ssh-keygen", "printf '%s\\n' '256 SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU github.com (ED25519)'");
  writeMock(binDir, "git", `
printf '%s\\n' "$*" >> "$MOCK_GIT_LOG"
if [ "\${1:-}" = "init" ]; then
  mkdir -p "\${3:?}/.git"
elif [ "\${1:-}" = "-C" ] && [ "\${3:-}" = "rev-parse" ]; then
  printf '%s\\n' "$MOCK_SOURCE_SHA"
fi
`);

  const secret = "PRIVATE_DEPLOY_KEY_CANARY";
  const result = spawnSync("bash", [HELPER, "echo", "git@github.com:Subunit-UG/echo-server.git", SHA], {
    encoding: "utf8",
    env: {
      ...process.env,
      GITHUB_WORKSPACE: workspace,
      RUNNER_TEMP: runnerTemp,
      SOURCE_DEPLOY_KEY: secret,
      MOCK_GIT_LOG: gitLog,
      MOCK_SOURCE_SHA: SHA,
      PATH: `${binDir}:${process.env.PATH}`,
    },
  });

  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, new RegExp(`PASS private-checkout-echo \\(source-sha=${SHA}\\)`));
  assert.doesNotMatch(result.stdout + result.stderr, new RegExp(secret));
  const calls = readFileSync(gitLog, "utf8");
  assert.match(calls, new RegExp(`fetch origin ${SHA}`));
  assert.match(calls, /fetch --depth 1 origin 5c37154c83464b1f5a203bd4e0f1d66af9bf75d1/);
  assert.doesNotMatch(calls, /checkout --detach FETCH_HEAD/);
  assert.match(calls, new RegExp(`checkout --detach ${SHA}`));
  assert.match(calls, /remote remove origin/);
  assert.equal(existsSync(join(runnerTemp, "scai-echo-deploy-key")), false);
  assert.equal(existsSync(join(runnerTemp, "scai-echo-known-hosts")), false);
  cleanup(testRoot);
});

test("an OpenSSH banner comment on stdout is ignored for host pinning (macOS runners)", () => {
  const testRoot = mkdtempSync(join(tmpdir(), "scai-private-success-test-"));
  const binDir = join(testRoot, "bin");
  const runnerTemp = join(testRoot, "runner-temp");
  const workspace = join(testRoot, "workspace");
  const gitLog = join(testRoot, "git-calls.log");
  mkdirSync(binDir);
  mkdirSync(runnerTemp);
  mkdirSync(workspace);
  writeMock(binDir, "ssh-keyscan", "printf '%s\\n' '# github.com:22 SSH-2.0-2097ddd' 'github.com ssh-ed25519 AAAAPINNED'");
  writeMock(binDir, "ssh-keygen", "printf '%s\\n' '256 SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU github.com (ED25519)'");
  writeMock(binDir, "git", `
printf '%s\\n' "$*" >> "$MOCK_GIT_LOG"
if [ "\${1:-}" = "init" ]; then
  mkdir -p "\${3:?}/.git"
elif [ "\${1:-}" = "-C" ] && [ "\${3:-}" = "rev-parse" ]; then
  printf '%s\\n' "$MOCK_SOURCE_SHA"
fi
`);

  const secret = "PRIVATE_DEPLOY_KEY_CANARY";
  const result = spawnSync("bash", [HELPER, "u1-chat", "git@github.com:Subunit-UG/infra-u1-chat.git", SHA], {
    encoding: "utf8",
    env: {
      ...process.env,
      GITHUB_WORKSPACE: workspace,
      RUNNER_TEMP: runnerTemp,
      SOURCE_DEPLOY_KEY: secret,
      MOCK_GIT_LOG: gitLog,
      MOCK_SOURCE_SHA: SHA,
      PATH: `${binDir}:${process.env.PATH}`,
    },
  });

  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, new RegExp(`PASS private-checkout-u1-chat \\(source-sha=${SHA}\\)`));
  assert.doesNotMatch(result.stdout + result.stderr, new RegExp(secret));
  const calls = readFileSync(gitLog, "utf8");
  assert.match(calls, new RegExp(`fetch --depth 1 origin ${SHA}`));
  assert.match(calls, new RegExp(`checkout --detach ${SHA}`));
  assert.match(calls, /remote remove origin/);
  assert.equal(existsSync(join(runnerTemp, "scai-u1-chat-deploy-key")), false);
  assert.equal(existsSync(join(runnerTemp, "scai-u1-chat-known-hosts")), false);
  cleanup(testRoot);
});

for (const component of ['sonar-tauri', 'bridge-tauri', 'trace-tauri']) test(`Sonar-Quellen verlangen je einen eigenen Deploy-Key: ${component}`, () => {
  const result = invoke([component, `git@github.com:Subunit-UG/${component}.git`, SHA], { SOURCE_DEPLOY_KEY: '' });
  assert.equal(result.status, 65);
  cleanup(result.testRoot);
});
for (const [name, tagSha, fetchStatus, status] of [
  ['leichter oder annotierter Tag stimmt', SHA, 0, 0],
  ['Tag zeigt auf anderen Commit', 'b'.repeat(40), 0, 67],
  ['Tag fehlt oder Transport scheitert', SHA, 1, 1],
]) test(`Komponenten-Drift-Guard: ${name}`, t => {
  const root = mkdtempSync(join(tmpdir(), 'sonar-tag-checkout-'));
  t.after(() => cleanup(root));
  const bin = join(root, 'bin'), runnerTemp = join(root, 'runner'), workspace = join(root, 'workspace');
  for (const path of [bin, runnerTemp, workspace]) mkdirSync(path);
  const gitLog = join(root, 'git.log');
  writeMock(bin, 'ssh-keyscan', "printf '%s\\n' 'github.com ssh-ed25519 AAAAPINNED'");
  writeMock(bin, 'ssh-keygen', "printf '%s\\n' '256 SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU github.com (ED25519)'");
  writeMock(bin, 'git', `
printf '%s\\n' "$*" >> "$MOCK_GIT_LOG"
if [ "\${1:-}" = init ]; then mkdir -p "\${3:?}/.git";
elif [ "\${3:-}" = rev-parse ]; then
  if [ "\${4:-}" = 'FETCH_HEAD^{commit}' ]; then printf '%s\\n' "$MOCK_TAG_SHA"; else printf '%s\\n' "$MOCK_SOURCE_SHA"; fi
elif [ "\${3:-}" = fetch ] && [[ "$*" == *refs/tags/* ]]; then exit "$MOCK_TAG_STATUS";
fi`);
  const secret = 'PRIVATE_DEPLOY_KEY_CANARY';
  const result = spawnSync('bash', [HELPER, 'bridge-tauri', 'git@github.com:Subunit-UG/bridge-tauri.git', SHA, 'v0.4.9'], {
    encoding: 'utf8', env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, RUNNER_TEMP: runnerTemp, GITHUB_WORKSPACE: workspace, SOURCE_DEPLOY_KEY: secret, MOCK_GIT_LOG: gitLog, MOCK_SOURCE_SHA: SHA, MOCK_TAG_SHA: tagSha, MOCK_TAG_STATUS: String(fetchStatus) },
  });
  assert.equal(result.status, status, result.stdout + result.stderr);
  assert.doesNotMatch(result.stdout + result.stderr, new RegExp(secret));
  assert.match(readFileSync(gitLog, 'utf8'), /fetch --depth 1 -- origin refs\/tags\/v0\.4\.9/);
  assert.equal(existsSync(join(runnerTemp, 'scai-bridge-tauri-deploy-key')), false);
  assert.equal(existsSync(join(runnerTemp, 'scai-bridge-tauri-known-hosts')), false);
});

for (const platform of ['MINGW64_NT-10.0', 'MSYS_NT-10.0', 'CYGWIN_NT-10.0']) {
  for (const failure of ['none', 'host', 'fetch', 'no-newline', 'no-hosts']) test(`Windows Git Bash recipe (${platform}, ${failure})`, t => {
    const root = mkdtempSync(join(tmpdir(), "checkout-win-' space-"));
    t.after(() => cleanup(root));
    const bin = join(root, 'bin'), runner = join(root, 'runner temp'), workspace = join(root, 'work space'), testHome = join(root, 'test home');
    for (const path of [bin, runner, workspace, join(testHome, '.ssh')]) mkdirSync(path, { recursive: true });
    const hosts = join(testHome, '.ssh/known_hosts'), gitLog = join(root, 'git.log'), sshLog = join(root, 'ssh.log');
    const previousHosts = failure === 'no-hosts' ? '' : 'github.com ssh-ed25519 PREEXISTING\nother.example ssh-ed25519 ORIGINAL' + (failure === 'no-newline' ? '' : '\n');
    if (failure !== 'no-hosts') writeFileSync(hosts, previousHosts);
    writeMock(bin, 'uname', 'printf "%s\\n" "$MOCK_PLATFORM"');
    writeMock(bin, 'cygpath', `
[ "$1" = -u ]
case "$2" in
  'D:\\a\\work space') printf '%s\\n' "$MOCK_WORKSPACE" ;;
  "$MOCK_RUNNER") printf '%s\\n' "$MOCK_RUNNER" ;;
  *) exit 99 ;;
esac`);
    writeMock(bin, 'ssh-keyscan', "printf '%s\\n' 'github.com ssh-ed25519 AAAAPINNED'");
    writeMock(bin, 'ssh-keygen', `
if [ "$MOCK_FAILURE" = host ]; then echo '256 SHA256:WRONG github.com (ED25519)';
else echo '256 SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU github.com (ED25519)'; fi`);
    writeMock(bin, 'ssh', `
printf '%s\\n' "$*" >> "$MOCK_SSH_LOG"
[ "$#" = 14 ] && [ "$1" = -i ] && [ "$3" = -F ] && [ "$4" = /dev/null ]
[ "$5" = -o ] && [ "$6" = IdentitiesOnly=yes ] && [ "$7" = -o ]
[ "$9" = -o ] && [ "\${10}" = GlobalKnownHostsFile=/dev/null ]
[ "\${11}" = -o ] && [ "\${12}" = HostKeyAlgorithms=ssh-ed25519 ]
[ "\${13}" = -o ] && [ "\${14}" = StrictHostKeyChecking=yes ]
case "$2" in "$HOME/.ssh/scai-checkout-credentials."*/key) ;; *) exit 99 ;; esac
[ -f "$2" ]
[ "$(cat "$2")" = PRIVATE_DEPLOY_KEY_CANARY ]
node - "$2" <<'NODE'
const fs = require('node:fs'), assert = require('node:assert/strict');
assert.equal(fs.statSync(process.argv[2]).mode & 0o777, 0o600);
NODE
[ "\${SOURCE_DEPLOY_KEY+x}" != x ]
[ "$8" = "UserKnownHostsFile=\${2%/key}/known_hosts" ]
[ "$(cat "\${8#UserKnownHostsFile=}")" = 'github.com ssh-ed25519 AAAAPINNED' ]
if [ "$MOCK_FAILURE" = fetch ]; then echo 'PRIVATE_FETCH_ERROR_CANARY' >&2; exit 128; fi`);
    writeMock(bin, 'git', `
printf '%s\\n' "$*" >> "$MOCK_GIT_LOG"
if [ "$1" = init ]; then mkdir -p "$3/.git";
elif [ "\${3:-}" = fetch ]; then
  grep -F 'config core.autocrlf false' "$MOCK_GIT_LOG" >/dev/null
  grep -F 'config core.eol lf' "$MOCK_GIT_LOG" >/dev/null
  case "$GIT_SSH_COMMAND" in 'ssh -i '*) ;; *) exit 99 ;; esac
  bash -c "$GIT_SSH_COMMAND"
elif [ "\${3:-}" = rev-parse ]; then printf '%s\\n' "$MOCK_SOURCE_SHA"; fi`);
    const result = spawnSync('bash', [HELPER, 'sonar-tauri', 'git@github.com:Subunit-UG/sonar-tauri.git', SHA], {
      encoding: 'utf8', env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, HOME: testHome, GITHUB_WORKSPACE: 'D:\\a\\work space', RUNNER_TEMP: runner, MOCK_PLATFORM: platform, MOCK_RUNNER: runner, MOCK_WORKSPACE: workspace, MOCK_SOURCE_SHA: SHA, SOURCE_DEPLOY_KEY: 'PRIVATE_DEPLOY_KEY_CANARY', MOCK_GIT_LOG: gitLog, MOCK_SSH_LOG: sshLog, MOCK_FAILURE: failure },
    });
    assert.equal(result.status, failure === 'host' ? 68 : failure === 'fetch' ? 128 : 0, result.stdout + result.stderr);
    assert.doesNotMatch(result.stdout + result.stderr, /PRIVATE_DEPLOY_KEY_CANARY|PRIVATE_FETCH_ERROR_CANARY/);
    if (failure === 'no-hosts') assert.equal(existsSync(hosts), false);
    else assert.equal(readFileSync(hosts, 'utf8'), previousHosts);
    assert.deepEqual(readdirSync(join(testHome, '.ssh')), failure === 'no-hosts' ? [] : ['known_hosts']);
    assert.deepEqual(readdirSync(runner).filter(n => n.startsWith('scai-checkout-credentials.')), []);
    assert.equal(existsSync(join(runner, 'scai-sonar-tauri-known-hosts')), false);
    if (failure !== 'host') assert.equal(readFileSync(sshLog, 'utf8').trim().split('\n').length, 1);
  });
}
