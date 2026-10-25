import assert from "node:assert/strict";
import { constants, createDecipheriv, createHash, generateKeyPairSync, privateDecrypt } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const workflow = readFileSync(join(ROOT, ".github/workflows/pr-check.yml"), "utf8");
const seal = workflow.split("      - name: Meet-Proof-Screenshots verschlüsseln")[1].split("\n      - name:")[0];
const upload = workflow.split("      - name: Meet-Proof-Screenshots (verschlüsselt) sichern")[1].split("\n      - name:")[0];
const condition = (step) => step.match(/^        if: (.+)$/m)[1];
const accepts = (step, proof, outcome = "skipped", sealed = "", key = "test-public-key") =>
  new Function("steps", "inputs", "always", `return ${condition(step)};`)(
    { meet_visual_proof: { outcome: proof }, meet_seal: { outcome, outputs: { sealed } } },
    { diagnostic_public_key_base64: key }, () => true,
  );
const productionDir = 'dir="$HOME/.cache/u1-shots/scai-meet-plugin/ci"';
const shell = seal.split("        run: |\n")[1].split("\n").map(line => line.replace(/^          /, "")).join("\n");
assert.equal(shell.split(productionDir).length, 2, "test relocates only the fixed proof directory");

function fixture(t, files) {
  const root = mkdtempSync(join(tmpdir(), "scai-meet-artifacts-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const proof = join(root, "proof");
  if (files !== "missing") mkdirSync(proof);
  if (files === "present") writeFileSync(join(proof, "scene.png"), "synthetic-meet-proof-bytes");
  symlinkSync(ROOT, join(root, "gate"), "dir");
  const output = join(root, "step-output");
  writeFileSync(output, "");
  return { root, proof, output };
}

function run(paths, key) {
  return spawnSync("bash", ["-c", shell.replace(productionDir, 'dir="$PROOF_TEST_DIR"')], {
    encoding: "utf8",
    env: { ...process.env, PROOF_TEST_DIR: paths.proof, RUNNER_TEMP: paths.root,
      GITHUB_WORKSPACE: paths.root, GITHUB_OUTPUT: paths.output,
      SCAI_ENCRYPTED_DIAGNOSTIC_PUBLIC_KEY_BASE64: key },
  });
}

test("skipped or cancelled Meet proof cannot package or upload an artifact", () => {
  for (const outcome of ["skipped", "cancelled", ""]) assert.equal(accepts(seal, outcome), false);
  for (const outcome of ["success", "failure"]) {
    assert.equal(accepts(seal, outcome), true);
    assert.equal(accepts(seal, outcome, "skipped", "", ""), false);
  }
  assert.equal(accepts(upload, "skipped", "skipped"), false);
  assert.equal(accepts(upload, "failure", "success"), false);
  assert.equal(accepts(upload, "failure", "failure", "true"), false);
});

test("missing or empty proof directory skips tar and never advertises an upload", t => {
  for (const files of ["missing", "empty"]) {
    const paths = fixture(t, files), result = run(paths, "not-needed-without-files");
    assert.equal(result.status, 0, result.stderr);
    assert.equal(readFileSync(paths.output, "utf8"), "");
    assert.equal(existsSync(join(paths.root, "scai-meet-shots.tgz")), false);
    assert.equal(existsSync(join(paths.root, "scai-meet-encrypted-shots.json")), false);
    assert.doesNotMatch(result.stderr, /tar:/);
    assert.equal(accepts(upload, "failure", "success"), false);
  }
});

test("present artifacts upload only after successful encryption and plaintext cleanup", t => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 3072 });
  const key = Buffer.from(publicKey.export({ type: "spki", format: "pem" })).toString("base64");
  const paths = fixture(t, "present"), result = run(paths, key);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(readFileSync(paths.output, "utf8"), "sealed=true\n");
  assert.equal(existsSync(join(paths.root, "scai-meet-shots.tgz")), false);
  const envelope = JSON.parse(readFileSync(join(paths.root, "scai-meet-encrypted-shots.json")));
  const contentKey = privateDecrypt({ key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, Buffer.from(envelope.wrapped_key, "base64"));
  const decipher = createDecipheriv("aes-256-gcm", contentKey, Buffer.from(envelope.iv, "base64"));
  decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
  const archive = Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, "base64")), decipher.final()]);
  assert.equal(createHash("sha256").update(archive).digest("hex"), envelope.plaintext_sha256);
  const content = spawnSync("tar", ["-xzOf", "-", "proof/scene.png"], { input: archive, encoding: "utf8" });
  assert.equal(content.status, 0, content.stderr);
  assert.equal(content.stdout, "synthetic-meet-proof-bytes");
  assert.equal(accepts(upload, "success", "success", "true"), true);
  assert.equal(accepts(upload, "failure", "success", "true"), true);

  const failed = fixture(t, "present"), rejected = run(failed, "invalid-test-key");
  assert.notEqual(rejected.status, 0);
  assert.equal(readFileSync(failed.output, "utf8"), "");
  assert.equal(existsSync(join(failed.root, "scai-meet-encrypted-shots.json")), false);
});
