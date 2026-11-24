import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, createHmac, generateKeyPairSync, randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { blake2b, open, seal } from "./sealed-box.mjs";
import { compareAll, KNOWN, sealAll, selftest } from "./seal-environment-secrets.mjs";

const TOOL = join(dirname(fileURLToPath(import.meta.url)), "seal-environment-secrets.mjs");
const hex = (text) => Buffer.from(text, "hex");
const LONG = "zertifikat-".repeat(30);

function pair() {
  const keys = generateKeyPairSync("x25519");
  return {
    publicKey: keys.publicKey.export({ format: "der", type: "spki" }).subarray(-32),
    privateKey: keys.privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32),
  };
}

test("BLAKE2b: gleiche Ausgabe wie die eingebaute Fassung, an den Blockgrenzen", () => {
  for (const length of [0, 1, 3, 64, 127, 128, 129, 255, 256, 257, 1000]) {
    const input = randomBytes(length);
    assert.deepEqual(blake2b(input, 64), createHash("blake2b512").update(input).digest(), `Länge ${length}`);
  }
  assert.equal(blake2b(Buffer.from("abc"), 64).toString("hex").slice(0, 32), "ba80a53f981c4d0d6a2797b69f12f6e9");
  assert.equal(blake2b(Buffer.from("abc"), 24).length, 24);
  assert.notDeepEqual(blake2b(Buffer.from("abc"), 24), blake2b(Buffer.from("abc"), 64).subarray(0, 24), "die Länge geht in den Wert ein");
});

test("ein mit libsodium versiegelter Wert lässt sich öffnen", () => {
  const derived = createHash("sha256").update(KNOWN.label).digest();
  assert.equal(open(hex(KNOWN.sealed), hex(KNOWN.publicKey), derived).toString("utf8"), "sealed box self-test ä\n");
  assert.equal(selftest(), true);
  const changed = hex(KNOWN.sealed);
  changed[40] ^= 1;
  assert.throws(() => open(changed, hex(KNOWN.publicKey), derived), /does not verify/);
});

test("versiegeln und öffnen: jede Länge, jedes Mal ein anderer Wert, 48 Byte Zuschlag", () => {
  const { publicKey, privateKey } = pair();
  for (const length of [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 1000, 5000]) {
    const message = randomBytes(length);
    const sealed = seal(message, publicKey);
    assert.equal(sealed.length, length + 48);
    assert.deepEqual(open(sealed, publicKey, privateKey), message, `Länge ${length}`);
  }
  assert.notDeepEqual(seal("x", publicKey), seal("x", publicKey));
});

test("veränderte, verkürzte und fremde Werte werden abgewiesen", () => {
  const { publicKey, privateKey } = pair();
  const other = pair();
  const sealed = seal("geheim", publicKey);
  for (const at of [0, 31, 32, 47, 48, sealed.length - 1]) {
    const changed = Buffer.from(sealed);
    changed[at] ^= 1;
    assert.throws(() => open(changed, publicKey, privateKey), `Byte ${at}`);
  }
  assert.throws(() => open(sealed.subarray(0, 47), publicKey, privateKey), /too short/);
  assert.throws(() => open(sealed, other.publicKey, other.privateKey), /does not verify/);
  assert.throws(() => seal("x", publicKey.subarray(0, 31)), /32 bytes/);
});

test("sealAll: jeder Wert bytegenau, auch mit Zeilenende und Umlauten; Prüfsummen mit Salz und Schlüssel", () => {
  const { publicKey, privateKey } = pair();
  const env = { V_A: `${LONG}\n`, V_B: "pässwort ", V_C: "x".repeat(6000), UNBETEILIGT: "nein" };
  const result = sealAll(["A", "B", "C"], env, publicKey.toString("base64"), "42");
  assert.deepEqual(result.missing, []);
  assert.equal(result.sealed.key_id, "42");
  assert.deepEqual(Object.keys(result.sealed.secrets), ["A", "B", "C"]);
  assert.match(result.digests.salt, /^[0-9a-f]{64}$/);
  const key = createHmac("sha256", hex(result.digests.salt)).update(env.V_A).digest();
  for (const name of ["A", "B", "C"]) {
    const value = env[`V_${name}`];
    assert.equal(open(Buffer.from(result.sealed.secrets[name], "base64"), publicKey, privateKey).toString("utf8"), value);
    assert.equal(result.digests.digests[name], createHmac("sha256", key).update(`${name}\0${value}`).digest("hex"));
    assert.notEqual(result.digests.digests[name], createHash("sha256").update(value).digest("hex"));
  }
  const again = sealAll(["A", "B", "C"], env, publicKey.toString("base64"), "42");
  assert.notEqual(again.digests.salt, result.digests.salt);
  for (const name of ["A", "B", "C"]) assert.notEqual(again.digests.digests[name], result.digests.digests[name]);
  assert.deepEqual(compareAll(["A", "B", "C"], env, again.digests), { lines: ["equal: A", "equal: B", "equal: C"], equal: true });
});

test("sealAll: ein leerer Wert, schlechte Namen, schlechter Schlüssel, kurze Schlüsselquelle, kein sauberer Text", () => {
  const key = pair().publicKey.toString("base64");
  assert.deepEqual(sealAll(["A", "B"], { V_A: "x" }, key, "1"), { missing: ["B"] });
  assert.throws(() => sealAll([], {}, key, "1"), /names/);
  assert.throws(() => sealAll(["A", "A"], { V_A: "x" }, key, "1"), /names/);
  assert.throws(() => sealAll(["a-b"], {}, key, "1"), /names/);
  assert.throws(() => sealAll(["A"], { V_A: "x" }, "kurz", "1"), /public key/);
  assert.throws(() => sealAll(["A"], { V_A: "x" }, key, "x1"), /key id/);
  assert.throws(() => sealAll(["A", "B"], { V_A: "x".repeat(255), V_B: LONG }, key, "1"), /long value/);
  assert.equal(sealAll(["A", "B"], { V_A: "x".repeat(256), V_B: "y" }, key, "1").missing.length, 0);
  assert.throws(() => sealAll(["A", "B"], { V_A: LONG, V_B: "pw\uFFFD" }, key, "1"), /not clean text: B/);
});

test("compareAll: gleich, anders, fehlt, nicht aufgezeichnet; ohne passende Schlüsselquelle unbestimmt", () => {
  const env = { V_A: LONG, V_B: "zwei", V_C: "drei" };
  const recorded = sealAll(["A", "B"], env, pair().publicKey.toString("base64"), "1").digests;
  const lines = (names, values, record = recorded) => compareAll(names, values, record).lines;
  assert.deepEqual(compareAll(["A", "B"], env, recorded), { lines: ["equal: A", "equal: B"], equal: true });
  assert.deepEqual(compareAll(["A", "B"], { V_A: LONG, V_B: "zwei\n" }, recorded), { lines: ["equal: A", "differs: B"], equal: false });
  assert.deepEqual(compareAll(["A", "B"], { V_A: LONG }, recorded), { lines: ["equal: A", "missing: B"], equal: false });
  assert.deepEqual(compareAll(["A", "C"], env, recorded), { lines: ["equal: A", "not recorded: C"], equal: false });
  assert.deepEqual(compareAll(["A", "B"], { V_A: `${LONG}x`, V_B: "zwei" }, recorded), { lines: ["differs: A", "undetermined: B"], equal: false });
  assert.deepEqual(compareAll(["A", "B"], { V_B: "zwei" }, recorded), { lines: ["missing: A", "undetermined: B"], equal: false });
  assert.deepEqual(lines(["A", "B"], { V_A: `${LONG}x` }), ["differs: A", "missing: B"]);
  assert.deepEqual(lines(["B", "A"], env), ["differs: B", "undetermined: A"]);
  assert.deepEqual(lines(["C", "B"], env), ["not recorded: C", "undetermined: B"]);
  assert.deepEqual(lines(["A", "B"], env, { digests: recorded.digests }), ["not recorded: A", "not recorded: B"]);
  assert.deepEqual(lines(["A", "B"], env, { salt: "00".repeat(32), digests: recorded.digests }), ["differs: A", "undetermined: B"]);
  assert.deepEqual(lines(["A", "B"], env, { salt: recorded.salt.toUpperCase(), digests: recorded.digests }), ["not recorded: A", "not recorded: B"]);
  assert.deepEqual(compareAll(["A"], { V_A: LONG }, {}), { lines: ["not recorded: A"], equal: false });
  assert.throws(() => compareAll(["A", "B"], { V_A: LONG, V_B: "pw\uFFFD" }, recorded), /not clean text: B/);
});

test("release-environment-secrets.yml: dieselben Namen in NAMES und in beiden Jobs, je als V_<NAME>", () => {
  const text = readFileSync(join(dirname(TOOL), "..", ".github", "workflows", "release-environment-secrets.yml"), "utf8");
  const names = text.match(/\n {2}NAMES: >-\n((?: {4}[A-Z0-9_ ]+\n)+)/)[1].trim().split(/\s+/);
  assert.equal(names.length, 14);
  assert.equal(new Set(names).size, names.length);
  const head = text.slice(0, text.indexOf("\njobs:\n"));
  assert.match(head, /\npermissions:\n {2}contents: read\n\n/);
  assert.equal(head.includes("actions:"), false);
  const jobs = text.slice(text.indexOf("\njobs:\n")).split(/\n {2}(?=[a-z]+:\n)/).slice(1);
  assert.deepEqual(jobs.map((job) => job.slice(0, job.indexOf(":"))), ["seal", "compare"]);
  for (const job of jobs) {
    assert.match(job, /\n {4}environment: release\n/);
    const mapped = [...job.matchAll(/^ {10}V_([A-Z0-9_]+): \$\{\{ secrets\.([A-Z0-9_]+) \}\}$/gm)];
    assert.deepEqual(mapped.map((m) => m[1]), names);
    assert.ok(mapped.every((m) => m[1] === m[2]));
    const other = [...job.matchAll(/secrets\.([A-Z0-9_]+)/g)].map((m) => m[1]).filter((name) => !names.includes(name));
    assert.deepEqual([...new Set(other)], job.startsWith("compare") ? ["RELEASE_HANDOVER_PRIVATE_KEY"] : []);
    assert.equal(job.includes("\n    permissions:\n      contents: read\n      actions: read\n"), job.startsWith("compare"));
    assert.equal(job.includes("permissions:"), job.startsWith("compare"));
  }
  const compare = jobs[1];
  const origin = compare.slice(compare.indexOf("Check the origin of the seal run"), compare.indexOf("Download the envelopes"));
  assert.ok(compare.indexOf("Check the run id") < compare.indexOf("Check the origin of the seal run"));
  for (const condition of [
    '.path == ".github/workflows/release-environment-secrets.yml"',
    '.event == "workflow_dispatch"',
    '.head_branch == "main"',
    '.status == "completed"',
    '.conclusion == "success"',
    ".repository.full_name == $repo",
    ".head_repository.full_name == $repo",
  ]) assert.ok(origin.includes(`${condition}\n`), condition);
  assert.equal(origin.includes("{{ secrets."), false);
  assert.equal(/gh secret|GH_TOKEN|RELEASE_ENV_MIGRATION_TOKEN/.test(text), false);
});

test("Aufruf: Dateien nur bei vollständigen Werten, kein Wert in der Ausgabe", () => {
  const dir = mkdtempSync(join(tmpdir(), "seal-test-"));
  try {
    const { publicKey, privateKey } = pair();
    const run = (args, env) => spawnSync(process.execPath, [TOOL, ...args], { env: { PATH: process.env.PATH, ...env }, encoding: "utf8" });
    const sealedPath = join(dir, "sealed.json");
    const digestsPath = join(dir, "digests.json");
    const args = ["seal", sealedPath, digestsPath, publicKey.toString("base64"), "7", "ONE", "TWO"];

    const one = "kennwort-eins-".repeat(20);
    const partial = run(args, { V_ONE: one });
    assert.equal(partial.status, 1);
    assert.equal(partial.stderr, "missing: TWO\n");
    assert.equal(existsSync(sealedPath) || existsSync(digestsPath), false);

    const unclean = spawnSync("/bin/sh", ["-c", `V_TWO="$(printf 'pw\\344')" exec "$0" "$@"`, process.execPath, TOOL, ...args], { env: { PATH: process.env.PATH, V_ONE: one }, encoding: "utf8" });
    assert.equal(unclean.status, 1);
    assert.equal(unclean.stderr, "failed: value is not clean text: TWO\n");
    assert.equal(existsSync(sealedPath) || existsSync(digestsPath), false);

    const full = run(args, { V_ONE: one, V_TWO: "kennwort-zwei\n" });
    assert.equal(full.status, 0, full.stderr);
    assert.equal(full.stdout, "sealed: ONE\nsealed: TWO\n");
    assert.equal(statSync(sealedPath).mode & 0o077, 0);
    const sealedText = readFileSync(sealedPath, "utf8");
    assert.equal(sealedText.includes("kennwort"), false);
    assert.equal(statSync(digestsPath).mode & 0o077, 0);
    assert.equal(readFileSync(digestsPath, "utf8").includes("kennwort"), false);
    const sealed = JSON.parse(sealedText);
    assert.equal(open(Buffer.from(sealed.secrets.TWO, "base64"), publicKey, privateKey).toString("utf8"), "kennwort-zwei\n");

    const same = run(["compare", digestsPath, "ONE", "TWO"], { V_ONE: one, V_TWO: "kennwort-zwei\n" });
    assert.equal(same.status, 0);
    assert.equal(same.stdout, "equal: ONE\nequal: TWO\n");
    const changed = run(["compare", digestsPath, "ONE", "TWO"], { V_ONE: one, V_TWO: "kennwort-zwei" });
    assert.equal(changed.status, 1);
    assert.equal(changed.stdout, "equal: ONE\ndiffers: TWO\n");
    const otherSource = run(["compare", digestsPath, "ONE", "TWO"], { V_ONE: `${one}x`, V_TWO: "kennwort-zwei\n" });
    assert.equal(otherSource.status, 1);
    assert.equal(otherSource.stdout, "differs: ONE\nundetermined: TWO\n");

    assert.equal(run(["selftest"], {}).stdout, "self-test passed\n");
    assert.equal(run(["seal", sealedPath], {}).status, 64);
    assert.equal(run(["compare", join(dir, "fehlt.json"), "ONE"], { V_ONE: "x" }).status, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
