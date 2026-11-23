import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const key = (options) => Buffer.from(generateKeyPairSync(...options).publicKey.export({ type: "spki", format: "pem" })).toString("base64");
const STRONG = key(["rsa", { modulusLength: 3072 }]);
const WEAK = key(["rsa", { modulusLength: 2048 }]);
const CURVE = key(["ec", { namedCurve: "P-256" }]);
const SHA = "0123456789abcdef0123456789abcdef01234567";
const NOTCH = { SOURCE_SHA: SHA, EXPECTED_VERSION: "1.2.3", SIGNING: "developer-id", ZENTRALE_SHA: SHA.replace(/0/g, "f"), ZENTRALE_VERSION: "0.4.0", RECIPIENT_PUBLIC_KEY_BASE64: STRONG };
const INTERNAL = { ...NOTCH, SIGNING: "development", ZENTRALE_SHA: "", ZENTRALE_VERSION: "" };
const CHARGE = { SOURCE_SHA: SHA, EXPECTED_VERSION: "10.0.12", RECIPIENT_PUBLIC_KEY_BASE64: STRONG };

function check(product, env, { handover = `${STRONG}\n`, args, arrange } = {}) {
  const root = mkdtempSync(join(tmpdir(), "build-request-"));
  try {
    mkdirSync(join(root, "scripts"));
    mkdirSync(join(root, "config"));
    copyFileSync(join(HERE, "check-signed-build-request.sh"), join(root, "scripts/check-signed-build-request.sh"));
    if (handover !== null) writeFileSync(join(root, "config/release-handover-public-key.b64"), handover);
    arrange?.(root);
    const result = spawnSync("bash", [join(root, "scripts/check-signed-build-request.sh"), ...(args ?? [product])], { encoding: "utf8", env: { PATH: process.env.PATH, ...env } });
    return { status: result.status, out: result.stdout + result.stderr };
  } finally { rmSync(root, { recursive: true, force: true }); }
}

test("in Ordnung: beide Signierwege der Notch und Charge", () => {
  const store = check("notch", NOTCH);
  assert.equal(store.status, 0, store.out);
  assert.equal(store.out, `PASS notch-build-request (source-sha=${SHA} version=1.2.3 signing=developer-id zentrale-sha=${NOTCH.ZENTRALE_SHA})\n`);
  const internal = check("notch", INTERNAL);
  assert.equal(internal.status, 0, internal.out);
  assert.match(internal.out, /signing=development zentrale-sha=none\)\n$/);
  const charge = check("charge", CHARGE);
  assert.equal(charge.status, 0, charge.out);
  assert.equal(charge.out, `PASS charge-build-request (source-sha=${SHA} version=10.0.12)\n`);
  // Zeilenumbrüche in der Schlüsseldatei stören nicht.
  assert.equal(check("charge", CHARGE, { handover: `${STRONG.replace(/(.{64})/g, "$1\n")}\n` }).status, 0);
});

function refused(name, product, env, options) {
  test(`abgewiesen: ${name}`, () => {
    const r = check(product, env, options);
    assert.equal(r.status, 1, r.out);
    assert.match(r.out, /^::error::[^\n]+\n$/);
    assert.doesNotMatch(r.out, /PASS/);
  });
}
refused("Pin zu kurz", "notch", { ...NOTCH, SOURCE_SHA: SHA.slice(0, 39) });
refused("Pin mit Großbuchstaben", "notch", { ...NOTCH, SOURCE_SHA: SHA.toUpperCase() });
refused("Pin ist ein Zweigname", "charge", { ...CHARGE, SOURCE_SHA: "main" });
refused("Pin mit zweiter Zeile", "charge", { ...CHARGE, SOURCE_SHA: `${SHA}\nmain` });
refused("Pin fehlt", "charge", { ...CHARGE, SOURCE_SHA: "" });
refused("Version mit Zusatz", "charge", { ...CHARGE, EXPECTED_VERSION: "1.2.3-beta" });
refused("Version mit zweiter Zeile", "notch", { ...NOTCH, EXPECTED_VERSION: "1.2.3\n9.9.9" });
refused("Version fehlt", "notch", { ...NOTCH, EXPECTED_VERSION: "" });
refused("unbekannter Signierweg", "notch", { ...NOTCH, SIGNING: "ad-hoc" });
refused("Signierweg fehlt", "notch", { ...NOTCH, SIGNING: "" });
refused("Store-Weg ohne Pin der Zentrale", "notch", { ...NOTCH, ZENTRALE_SHA: "" });
refused("Store-Weg mit kurzem Pin der Zentrale", "notch", { ...NOTCH, ZENTRALE_SHA: "abc123" });
refused("Store-Weg ohne Version der Zentrale", "notch", { ...NOTCH, ZENTRALE_VERSION: "" });
refused("interner Weg mit Pin der Zentrale", "notch", { ...INTERNAL, ZENTRALE_SHA: NOTCH.ZENTRALE_SHA });
refused("interner Weg mit Version der Zentrale", "notch", { ...INTERNAL, ZENTRALE_VERSION: "0.4.0" });
refused("Empfängerschlüssel fehlt", "charge", { ...CHARGE, RECIPIENT_PUBLIC_KEY_BASE64: "" });
refused("Empfängerschlüssel zu kurz", "charge", { ...CHARGE, RECIPIENT_PUBLIC_KEY_BASE64: WEAK });
refused("Empfängerschlüssel ist kein RSA", "notch", { ...NOTCH, RECIPIENT_PUBLIC_KEY_BASE64: CURVE });
refused("Empfängerschlüssel ist kein Schlüssel", "notch", { ...NOTCH, RECIPIENT_PUBLIC_KEY_BASE64: "bm9wZQ==" });
refused("Übergabe-Schlüssel fehlt", "charge", CHARGE, { handover: null });
refused("Übergabe-Schlüssel ist leer", "charge", CHARGE, { handover: "" });
refused("Übergabe-Schlüssel zu kurz", "notch", NOTCH, { handover: `${WEAK}\n` });
refused("Übergabe-Schlüssel ist kein Schlüssel", "notch", NOTCH, { handover: "bm9wZQ==\n" });
refused("Übergabe-Schlüssel ist ein Verweis", "charge", CHARGE, {
  handover: null,
  arrange: (root) => { writeFileSync(join(root, "fremd.b64"), `${STRONG}\n`); symlinkSync(join(root, "fremd.b64"), join(root, "config/release-handover-public-key.b64")); },
});

test("Aufruf: genau ein bekanntes Produkt", () => {
  assert.equal(check("notch", NOTCH, { args: [] }).status, 64);
  assert.equal(check("notch", NOTCH, { args: ["sonar"] }).status, 64);
  assert.equal(check("notch", NOTCH, { args: ["notch", "charge"] }).status, 64);
});
