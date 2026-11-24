#!/usr/bin/env node
// seal      reads V_<NAME> from the environment and writes two files: every value sealed for a public
//           key (the form the secrets API takes as encrypted_value) and a SHA-256 digest of every value.
// compare   reads V_<NAME> and reports per name whether its digest equals the recorded one.
// selftest  opens a known sealed value and seals and opens fresh ones.
// Nothing derived from a value is printed: output is names and one word per name.
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { open, seal } from "./sealed-box.mjs";

const NAME = /^[A-Z][A-Z0-9_]*$/;
const digest = (value) => createHash("sha256").update(Buffer.from(value, "utf8")).digest("hex");

function valuesOf(names, env) {
  if (names.length === 0 || new Set(names).size !== names.length || !names.every((name) => NAME.test(name))) {
    throw new Error("names must be unique and well-formed");
  }
  return names.map((name) => [name, env[`V_${name}`] ?? ""]);
}

export function sealAll(names, env, publicKeyBase64, keyId) {
  const publicKey = Buffer.from(publicKeyBase64, "base64");
  if (publicKey.length !== 32 || publicKey.toString("base64") !== publicKeyBase64) throw new Error("public key must be 32 bytes in base64");
  if (!/^[0-9]+$/.test(keyId)) throw new Error("key id must be a number");
  const values = valuesOf(names, env);
  const missing = values.filter(([, value]) => value === "").map(([name]) => name);
  if (missing.length > 0) return { missing };
  return {
    missing,
    sealed: { key_id: keyId, secrets: Object.fromEntries(values.map(([name, value]) => [name, seal(Buffer.from(value, "utf8"), publicKey).toString("base64")])) },
    digests: { digests: Object.fromEntries(values.map(([name, value]) => [name, digest(value)])) },
  };
}

export function compareAll(names, env, recorded) {
  const expected = recorded?.digests ?? {};
  const lines = valuesOf(names, env).map(([name, value]) => {
    if (value === "") return `missing: ${name}`;
    if (typeof expected[name] !== "string") return `not recorded: ${name}`;
    return `${digest(value) === expected[name] ? "equal" : "differs"}: ${name}`;
  });
  return { lines, equal: lines.every((line) => line.startsWith("equal: ")) };
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

function main([mode, ...rest], env) {
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
  console.error("usage: seal-environment-secrets.mjs selftest | seal <sealed.json> <digests.json> <public-key-base64> <key-id> NAME... | compare <digests.json> NAME...");
  return 64;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    process.exitCode = main(process.argv.slice(2), process.env);
  } catch (error) {
    console.error(`failed: ${error.message}`);
    process.exitCode = 1;
  }
}
