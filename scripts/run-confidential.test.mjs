import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { constants, createDecipheriv, createHash, generateKeyPairSync, privateDecrypt } from "node:crypto";
import test from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const RUNNER = join(ROOT, "scripts/run-confidential.sh");

function invoke(label, script, env = {}) {
  const runnerTemp = mkdtempSync(join(tmpdir(), "scai-confidential-test-"));
  const extraEnv = typeof env === "function" ? env(runnerTemp) : env;
  const result = spawnSync(
    "bash",
    [RUNNER, label, "bash", "-c", script],
    { encoding: "utf8", env: { ...process.env, RUNNER_TEMP: runnerTemp, ...extraEnv } },
  );
  return { ...result, runnerTemp };
}

function assertNoRetainedLogs(runnerTemp) {
  const logDir = join(runnerTemp, "scai-confidential-logs");
  assert.equal(existsSync(logDir), true);
  assert.deepEqual(readdirSync(logDir), []);
  rmSync(runnerTemp, { recursive: true, force: true });
}

test("successful private output is replaced by a digest-only PASS", () => {
  const marker = "PRIVATE_SOURCE_CANARY_SUCCESS";
  const result = invoke("success-check", `printf '${marker}\\n'`);
  assert.equal(result.status, 0);
  assert.doesNotMatch(result.stdout + result.stderr, new RegExp(marker));
  assert.match(result.stdout, /^PASS success-check \(private-log-sha256=[0-9a-f]{64}, bytes=30\)\n$/);
  assertNoRetainedLogs(result.runnerTemp);
});

test("failed private output is suppressed while the original exit code survives", () => {
  const marker = "PRIVATE_SOURCE_CANARY_FAILURE";
  const result = invoke("failure-check", `printf '${marker}\\n' >&2; exit 23`);
  assert.equal(result.status, 23);
  assert.doesNotMatch(result.stdout + result.stderr, new RegExp(marker));
  assert.match(result.stdout, /failure-check failed with exit 23; private output suppressed/);
  assertNoRetainedLogs(result.runnerTemp);
});

test("digest stays plain hexadecimal when the temporary path contains a backslash", () => {
  const runnerRoot = mkdtempSync(join(tmpdir(), "scai-confidential-test-"));
  const runnerTemp = join(runnerRoot, "windows\\path");
  mkdirSync(runnerTemp);
  const result = spawnSync(
    "bash",
    [RUNNER, "windows-path-check", "bash", "-c", "printf 'private\\n'"],
    { encoding: "utf8", env: { ...process.env, RUNNER_TEMP: runnerTemp } },
  );
  assert.equal(result.status, 0);
  assert.match(result.stdout, /^PASS windows-path-check \(private-log-sha256=[0-9a-f]{64}, bytes=8\)\n$/);
  assertNoRetainedLogs(runnerTemp);
  rmSync(runnerRoot, { recursive: true, force: true });
});

test("labels cannot inject workflow commands or filesystem paths", () => {
  const runnerTemp = mkdtempSync(join(tmpdir(), "scai-confidential-test-"));
  const result = spawnSync(
    "bash",
    [RUNNER, "../::warning::bad", "true"],
    { encoding: "utf8", env: { ...process.env, RUNNER_TEMP: runnerTemp } },
  );
  assert.equal(result.status, 64);
  assert.match(result.stderr, /invalid confidential command label/);
  assert.deepEqual(readdirSync(runnerTemp), []);
  rmSync(runnerTemp, { recursive: true, force: true });
});

test("failed private output can leave the runner only as a one-time encrypted envelope", () => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 3072 });
  const publicKeyBase64 = Buffer.from(publicKey.export({ type: "spki", format: "pem" })).toString("base64");
  const marker = "PRIVATE_ENCRYPTED_DIAGNOSTIC_CANARY";
  const sealed = invoke("encrypted-failure", `printf '${marker}\\n' >&2; exit 27`, (runnerTemp) => ({
    SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64: publicKeyBase64,
    SCAI_ENCRYPTED_DIAGNOSTIC_PATH: join(runnerTemp, "diagnostic.json"),
  }));
  const diagnosticPath = join(sealed.runnerTemp, "diagnostic.json");
  assert.equal(sealed.status, 27);
  assert.doesNotMatch(sealed.stdout + sealed.stderr, new RegExp(marker));
  assert.equal(existsSync(diagnosticPath), true);

  const envelope = JSON.parse(readFileSync(diagnosticPath, "utf8"));
  const contentKey = privateDecrypt({
    key: privateKey,
    padding: constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: "sha256",
  }, Buffer.from(envelope.wrapped_key, "base64"));
  const decipher = createDecipheriv("aes-256-gcm", contentKey, Buffer.from(envelope.iv, "base64"));
  decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, "base64")),
    decipher.final(),
  ]);
  assert.equal(plaintext.toString("utf8"), `${marker}\n`);
  assert.equal(createHash("sha256").update(plaintext).digest("hex"), envelope.plaintext_sha256);
  assertNoRetainedLogs(sealed.runnerTemp);
});

test("invalid diagnostic keys fail closed without claiming that an envelope was sealed", () => {
  const marker = "PRIVATE_INVALID_KEY_CANARY";
  const sealed = invoke("invalid-key-failure", `printf '${marker}\\n' >&2; exit 29`, (runnerTemp) => ({
    SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64: Buffer.from("not a PEM public key").toString("base64"),
    SCAI_ENCRYPTED_DIAGNOSTIC_PATH: join(runnerTemp, "diagnostic.json"),
  }));
  const publicOutput = sealed.stdout + sealed.stderr;
  assert.equal(sealed.status, 70);
  assert.doesNotMatch(publicOutput, new RegExp(marker));
  assert.doesNotMatch(publicOutput, /private failure log sealed/);
  assert.match(publicOutput, /Encrypted diagnostic unavailable/);
  assert.equal(existsSync(join(sealed.runnerTemp, "diagnostic.json")), false);
  assertNoRetainedLogs(sealed.runnerTemp);
});

function decryptEnvelope(path, privateKey) {
  const envelope = JSON.parse(readFileSync(path, 'utf8'));
  const key = privateDecrypt({ key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, Buffer.from(envelope.wrapped_key, 'base64'));
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
  const plaintext = Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, 'base64')), decipher.final()]);
  assert.equal(createHash('sha256').update(plaintext).digest('hex'), envelope.plaintext_sha256);
  return plaintext.toString('utf8');
}

test('nested failures and repeated labels preserve every encrypted envelope without public plaintext', () => {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 3072 });
  const result = invoke('outer', `
bash "$TEST_RUNNER" same-label bash -c 'echo PRIVATE_FIRST_FETCH_CANARY; exit 128'
cp "$SCAI_ENCRYPTED_DIAGNOSTIC_PATH" "$RUNNER_TEMP/original-envelope"
bash "$TEST_RUNNER" same-label bash -c 'echo PRIVATE_SECOND_FETCH_CANARY; exit 128'
exit 128`, runnerTemp => ({
    TEST_RUNNER: RUNNER,
    SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64: Buffer.from(publicKey.export({ type: 'spki', format: 'pem' })).toString('base64'),
    SCAI_ENCRYPTED_DIAGNOSTIC_PATH: join(runnerTemp, 'sonar-diagnostic.json'),
  }));
  assert.equal(result.status, 128, result.stdout + result.stderr);
  assert.doesNotMatch(result.stdout + result.stderr, /PRIVATE_(FIRST|SECOND)_FETCH_CANARY/);
  const paths = readdirSync(result.runnerTemp).filter(name => name.endsWith('.json')).sort();
  assert.deepEqual(paths, ['sonar-diagnostic-outer-1.json', 'sonar-diagnostic-same-label-1.json', 'sonar-diagnostic.json']);
  assert.equal(decryptEnvelope(join(result.runnerTemp, 'sonar-diagnostic.json'), privateKey), 'PRIVATE_FIRST_FETCH_CANARY\n');
  assert.equal(decryptEnvelope(join(result.runnerTemp, 'sonar-diagnostic-same-label-1.json'), privateKey), 'PRIVATE_SECOND_FETCH_CANARY\n');
  assert.match(decryptEnvelope(join(result.runnerTemp, 'sonar-diagnostic-outer-1.json'), privateKey), /same-label failed with exit 128/);
  assert.deepEqual(readFileSync(join(result.runnerTemp, 'sonar-diagnostic.json')), readFileSync(join(result.runnerTemp, 'original-envelope')));
  assert.equal(readdirSync(result.runnerTemp).some(name => name.startsWith('scai-sealed.')), false);
  assertNoRetainedLogs(result.runnerTemp);
});

test('concurrent confidential failures atomically retain separate complete envelopes', () => {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 3072 });
  const result = invoke('parallel-outer', `
bash "$TEST_RUNNER" parallel bash -c 'echo PRIVATE_CONCURRENT_A; exit 7' &
first=$!
bash "$TEST_RUNNER" parallel bash -c 'echo PRIVATE_CONCURRENT_B; exit 9' &
second=$!
wait "$first"
wait "$second"
exit 11`, runnerTemp => ({
    TEST_RUNNER: RUNNER,
    SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64: Buffer.from(publicKey.export({ type: 'spki', format: 'pem' })).toString('base64'),
    SCAI_ENCRYPTED_DIAGNOSTIC_PATH: join(runnerTemp, 'sonar-diagnostic.json'),
  }));
  assert.equal(result.status, 11, result.stdout + result.stderr);
  const paths = readdirSync(result.runnerTemp).filter(name => name.endsWith('.json'));
  assert.equal(paths.length, 3);
  const plaintexts = paths.map(name => decryptEnvelope(join(result.runnerTemp, name), privateKey));
  assert.ok(plaintexts.includes('PRIVATE_CONCURRENT_A\n'));
  assert.ok(plaintexts.includes('PRIVATE_CONCURRENT_B\n'));
  assert.doesNotMatch(result.stdout + result.stderr, /PRIVATE_CONCURRENT/);
  assertNoRetainedLogs(result.runnerTemp);
});

for (const path of ['not-an-envelope.log', '../escaped.json', 'nested/../../escaped.json']) test(`diagnostic destination rejects ${path}`, () => {
  const result = invoke('invalid-path', 'echo PRIVATE_PATH_CANARY; exit 1', runnerTemp => ({
    SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64: 'fixture',
    SCAI_ENCRYPTED_DIAGNOSTIC_PATH: `${runnerTemp}/${path}`,
  }));
  assert.equal(result.status, 64);
  assert.doesNotMatch(result.stdout + result.stderr, /PRIVATE_PATH_CANARY/);
  assertNoRetainedLogs(result.runnerTemp);
});


test('step-scoped encrypted glob retains all three nested failures and excludes raw or foreign files', () => {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 3072 });
  const workflow = readFileSync(join(ROOT, '.github/workflows/pr-check.yml'), 'utf8');
  const producer = workflow.split(/^      - name: /m).find(step => step.includes('id: plugin_deploy_tests'));
  const directory = producer.match(/format\('\{0\}\/([^/]+)\/failure\.encrypted\.json'/)[1];
  const upload = workflow.split(/^      - name: /m).find(step => step.includes("steps.plugin_deploy_tests.outcome == 'failure'"));
  assert.ok(upload.includes(`path: \${{ runner.temp }}/${directory}/*.encrypted.json`));
  const result = invoke('outer', `
echo RAW_NOT_UPLOADABLE > "$DIAG_DIR/raw.log"
echo RAW_JSON_NOT_UPLOADABLE > "$DIAG_DIR/raw.json"
echo FOREIGN_NOT_UPLOADABLE > "$RUNNER_TEMP/foreign.encrypted.json"
bash "$TEST_RUNNER" same-label bash -c 'echo PRIVATE_FIRST_CANARY; exit 7'
bash "$TEST_RUNNER" same-label bash -c 'echo PRIVATE_SECOND_CANARY; exit 8'
exit 9`, runnerTemp => {
    const dir = join(runnerTemp, directory);
    mkdirSync(dir, { mode: 0o700 });
    return {
      TEST_RUNNER: RUNNER, DIAG_DIR: dir,
      SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64: Buffer.from(publicKey.export({ type: 'spki', format: 'pem' })).toString('base64'),
      SCAI_ENCRYPTED_DIAGNOSTIC_PATH: join(dir, 'failure.encrypted.json'),
    };
  });
  try {
    assert.ifError(result.error);
    assert.equal(result.status, 9, result.stdout + result.stderr);
    assert.doesNotMatch(result.stdout + result.stderr, /PRIVATE_(FIRST|SECOND)_CANARY/);
    // Exercise the exact non-recursive upload glob from the actual workflow.
    const glob = upload.match(/^          path: (.+)$/m)[1].replace('${{ runner.temp }}', result.runnerTemp);
    const selected = spawnSync('bash', ['-c', 'printf "%s\\n" "$DIAG_DIR"/*.encrypted.json'], {
      encoding: 'utf8', env: { ...process.env, DIAG_DIR: join(result.runnerTemp, directory) },
    });
    assert.ifError(selected.error);
    assert.equal(selected.status, 0);
    assert.equal(glob, `${join(result.runnerTemp, directory)}/*.encrypted.json`);
    const paths = selected.stdout.trim().split('\n').sort();
    assert.deepEqual(paths, ['failure-outer-1.encrypted.json', 'failure-same-label-1.encrypted.json', 'failure.encrypted.json'].map(name => join(result.runnerTemp, directory, name)));
    const plain = paths.map(path => decryptEnvelope(path, privateKey));
    assert.ok(plain.includes('PRIVATE_FIRST_CANARY\n'));
    assert.ok(plain.includes('PRIVATE_SECOND_CANARY\n'));
    assert.ok(plain.some(value => value.includes('same-label failed with exit 8')));
    assertNoRetainedLogs(result.runnerTemp);
  } finally { rmSync(result.runnerTemp, { recursive: true, force: true }); }
});
