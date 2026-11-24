#!/usr/bin/env node
// seal      reads V_<NAME> from the environment and writes two files: every value sealed for a public
//           key (the form the secrets API takes as encrypted_value) and a keyed digest of every value.
// compare   reads V_<NAME> and reports per name whether its digest equals the recorded one.
// origin    asks the API for a run and accepts only a completed, successful workflow_dispatch run of the
//           given workflow file on main of this repository, in its first attempt: a re-run keeps its id
//           and would record whatever the job sees by then.
// selftest  opens a known sealed value and seals and opens fresh ones.
// The value of the first name keys every digest, so that name must hold a long random value (a
// certificate or a private key): a digest of a short value cannot be tested against guesses without it.
// A fresh salt per seal makes the digests of two runs differ.
// Nothing derived from a value is printed: output is names and one word per name.
import { createHash, createHmac, generateKeyPairSync, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { open, seal } from "./sealed-box.mjs";

const NAME = /^[A-Z][A-Z0-9_]*$/;
const KEY_SOURCE_MIN = 256;
const hmac = (key, ...parts) => parts.reduce((mac, part) => mac.update(part), createHmac("sha256", key)).digest();

// A value that does not decode as text arrives with replacement characters; sealing it would store
// different bytes than the original while both sides still agree on the digest.
function valuesOf(names, env) {
  if (names.length === 0 || new Set(names).size !== names.length || !names.every((name) => NAME.test(name))) {
    throw new Error("names must be unique and well-formed");
  }
  return names.map((name) => {
    const value = env[`V_${name}`] ?? "";
    if (value.includes("�")) throw new Error(`value is not clean text: ${name}`);
    return [name, value];
  });
}

function digester(salt, keySource) {
  const key = hmac(salt, Buffer.from(keySource, "utf8"));
  return (name, value) => hmac(key, `${name}\0`, Buffer.from(value, "utf8")).toString("hex");
}

export function sealAll(names, env, publicKeyBase64, keyId) {
  const publicKey = Buffer.from(publicKeyBase64, "base64");
  if (publicKey.length !== 32 || publicKey.toString("base64") !== publicKeyBase64) throw new Error("public key must be 32 bytes in base64");
  if (!/^[0-9]+$/.test(keyId)) throw new Error("key id must be a number");
  const values = valuesOf(names, env);
  const missing = values.filter(([, value]) => value === "").map(([name]) => name);
  if (missing.length > 0) return { missing };
  if (values[0][1].length < KEY_SOURCE_MIN) throw new Error("the first name must hold a long value");
  const salt = randomBytes(32);
  const digestOf = digester(salt, values[0][1]);
  return {
    missing,
    sealed: { key_id: keyId, secrets: Object.fromEntries(values.map(([name, value]) => [name, seal(Buffer.from(value, "utf8"), publicKey).toString("base64")])) },
    digests: { salt: salt.toString("hex"), digests: Object.fromEntries(values.map(([name, value]) => [name, digestOf(name, value)])) },
  };
}

// Without the recorded value of the first name there is no key, so the other names stay undetermined.
export function compareAll(names, env, recorded) {
  const expected = recorded?.digests ?? {};
  const salt = /^[0-9a-f]{64}$/.test(recorded?.salt ?? "") ? Buffer.from(recorded.salt, "hex") : null;
  const values = valuesOf(names, env);
  const [sourceName, source] = values[0];
  const digestOf = salt !== null && source !== "" ? digester(salt, source) : null;
  const sourceEqual = digestOf !== null && typeof expected[sourceName] === "string" && digestOf(sourceName, source) === expected[sourceName];
  const lines = values.map(([name, value], index) => {
    if (value === "") return `missing: ${name}`;
    if (salt === null || typeof expected[name] !== "string") return `not recorded: ${name}`;
    if (index > 0 && !sourceEqual) return `undetermined: ${name}`;
    return `${digestOf(name, value) === expected[name] ? "equal" : "differs"}: ${name}`;
  });
  return { lines, equal: lines.every((line) => line.startsWith("equal: ")) };
}

export function isSealRun(run, repository, workflowPath) {
  if (typeof repository !== "string" || repository === "" || typeof workflowPath !== "string" || workflowPath === "") return false;
  return run?.path === workflowPath && run.event === "workflow_dispatch" && run.head_branch === "main"
    && run.status === "completed" && run.conclusion === "success" && run.run_attempt === 1
    && run.repository?.full_name === repository && run.head_repository?.full_name === repository;
}

async function originOf(runId, workflowPath, env) {
  if (!/^[0-9]{1,20}$/.test(runId)) throw new Error("run id must be a number");
  const response = await fetch(`${env.GITHUB_API_URL}/repos/${env.GITHUB_REPOSITORY}/actions/runs/${runId}`, {
    headers: { accept: "application/vnd.github+json", authorization: `Bearer ${env.RUN_LOOKUP_TOKEN}` },
  });
  return response.ok && isSealRun(await response.json(), env.GITHUB_REPOSITORY, workflowPath);
}

// A value sealed with libsodium for the test key pair whose private half is the SHA-256 of KNOWN.label.
export const KNOWN = {
  label: "sealed-box self-test",
  publicKey: "0bf0eb80fa52687d12501194bb05b79e98b79913c0bc17a2f044e8d1e3a18d2e",
  message: "sealed box self-test ä\n",
  sealed: "053cfb811015de15b1a6d71dc7fab469d9179aaadf26708b80d9920b231f1f5e5f4e54c71de8760f267ae2810d45f8378bef14f5be86da58853a6fee67f80ad785faf1a448e074fa",
};

export function selftest() {
  const hex = (text) => Buffer.from(text, "hex");
  if (typeof fetch !== "function") return false;
  const known = open(hex(KNOWN.sealed), hex(KNOWN.publicKey), createHash("sha256").update(KNOWN.label).digest());
  if (known.toString("utf8") !== KNOWN.message) return false;
  const pair = generateKeyPairSync("x25519");
  const publicKey = pair.publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  const privateKey = pair.privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32);
  return [0, 1, 16, 17, 64, 65, 4096].every((length) => {
    const message = randomBytes(length);
    return open(seal(message, publicKey), publicKey, privateKey).equals(message);
  });
}

async function main([mode, ...rest], env) {
  if (mode === "selftest" && rest.length === 0) {
    if (!selftest()) throw new Error("self-test failed");
    console.log("self-test passed");
    return 0;
  }
  if (mode === "seal" && rest.length > 4) {
    const [sealedPath, digestsPath, publicKey, keyId, ...names] = rest;
    const result = sealAll(names, env, publicKey, keyId);
    if (result.missing.length > 0) {
      for (const name of result.missing) console.error(`missing: ${name}`);
      return 1;
    }
    writeFileSync(sealedPath, `${JSON.stringify(result.sealed)}\n`, { mode: 0o600 });
    writeFileSync(digestsPath, `${JSON.stringify(result.digests)}\n`, { mode: 0o600 });
    for (const name of names) console.log(`sealed: ${name}`);
    return 0;
  }
  if (mode === "compare" && rest.length > 1) {
    const [digestsPath, ...names] = rest;
    const result = compareAll(names, env, JSON.parse(readFileSync(digestsPath, "utf8")));
    for (const line of result.lines) console.log(line);
    return result.equal ? 0 : 1;
  }
  if (mode === "origin" && rest.length === 2) {
    const accepted = await originOf(rest[0], rest[1], env);
    console.log(accepted ? "origin accepted" : "origin rejected");
    return accepted ? 0 : 1;
  }
  console.error("usage: seal-environment-secrets.mjs selftest | seal <sealed.json> <digests.json> <public-key-base64> <key-id> NAME... | compare <digests.json> NAME... | origin <run-id> <workflow-path>");
  return 64;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    process.exitCode = await main(process.argv.slice(2), process.env);
  } catch (error) {
    console.error(`failed: ${error.message}`);
    process.exitCode = 1;
  }
}
