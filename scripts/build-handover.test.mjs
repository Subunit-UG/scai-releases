import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import {
  chmodSync, copyFileSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, readlinkSync, rmSync,
  statSync, symlinkSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const TOOLS = ["pack-app-bundle.py", "extract-app-bundle.py", "seal-build-handover.sh", "open-build-handover.sh", "encrypt-confidential-log.mjs", "decrypt-confidential-envelope.mjs"];
const MARKER = "KLARTEXT-MARKE-7f3a";
const pair = (bits = 3072) => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: bits });
  return {
    publicBase64: Buffer.from(publicKey.export({ type: "spki", format: "pem" })).toString("base64"),
    privatePem: privateKey.export({ type: "pkcs8", format: "pem" }),
  };
};
const KEYS = pair();
const OTHER = pair();
const sha256 = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");

// Ein eigener Baum wie im Lauf: scripts/ neben config/ mit dem öffentlichen Übergabe-Schlüssel.
function fixture({ key = `${KEYS.publicBase64}\n` } = {}) {
  const root = mkdtempSync(join(tmpdir(), "build-handover-"));
  mkdirSync(join(root, "gate/scripts"), { recursive: true });
  mkdirSync(join(root, "gate/config"));
  for (const tool of TOOLS) copyFileSync(join(HERE, tool), join(root, "gate/scripts", tool));
  if (key !== null) writeFileSync(join(root, "gate/config/release-handover-public-key.b64"), key);
  mkdirSync(join(root, "temp"));
  const app = join(root, "bau/Probe.app");
  const framework = join(app, "Contents/Resources/x/F.framework");
  mkdirSync(join(app, "Contents/MacOS"), { recursive: true });
  mkdirSync(join(framework, "Versions/A/Resources"), { recursive: true });
  writeFileSync(join(app, "Contents/MacOS/Probe"), `programm ${MARKER}`);
  chmodSync(join(app, "Contents/MacOS/Probe"), 0o755);
  writeFileSync(join(app, "Contents/Info.plist"), "<plist/>");
  writeFileSync(join(framework, "Versions/A/F"), Buffer.from([0, 1, 2, 255]));
  chmodSync(join(framework, "Versions/A/F"), 0o755);
  writeFileSync(join(framework, "Versions/A/Resources/Info.plist"), "<plist/>");
  mkdirSync(join(app, "Contents/Resources/leer"));
  symlinkSync("A", join(framework, "Versions/Current"));
  symlinkSync("Versions/Current/F", join(framework, "F"));
  symlinkSync("Versions/Current/Resources", join(framework, "Resources"));
  const env = { PATH: process.env.PATH, RUNNER_TEMP: join(root, "temp"), GITHUB_OUTPUT: join(root, "output") };
  writeFileSync(env.GITHUB_OUTPUT, "");
  const sh = (script, args, extra = {}) => {
    const result = spawnSync("bash", [join(root, "gate/scripts", script), ...args], { encoding: "utf8", env: { ...env, ...extra } });
    return { status: result.status, out: result.stdout + result.stderr };
  };
  const py = (script, args) => {
    const result = spawnSync("python3", ["-I", join(root, "gate/scripts", script), ...args], { encoding: "utf8", env: { PATH: process.env.PATH } });
    return { status: result.status, out: result.stdout + result.stderr };
  };
  return { root, app, env, sh, py, out: join(root, "uebergabe"), work: join(root, "arbeit"), close: () => rmSync(root, { recursive: true, force: true }) };
}

function picture(dir, base = dir, found = {}) {
  for (const name of readdirSync(dir).sort()) {
    const path = join(dir, name);
    const info = lstatSync(path);
    const key = path.slice(base.length + 1);
    if (info.isSymbolicLink()) found[key] = `link ${readlinkSync(path)}`;
    else if (info.isDirectory()) { found[key] = "dir"; picture(path, base, found); }
    else found[key] = `file ${info.mode & 0o111 ? "x" : "-"} ${sha256(path)}`;
  }
  return found;
}
const sealed = (f) => {
  const r = f.sh("seal-build-handover.sh", [f.app, f.out]);
  assert.equal(r.status, 0, r.out);
  return readFileSync(f.env.GITHUB_OUTPUT, "utf8").match(/^sha256=([0-9a-f]{64})\n$/)[1];
};
const open = (f, digest, key = KEYS.privatePem, extra = {}) => f.sh("open-build-handover.sh", [f.out, f.work], { HANDOVER_SHA256: digest, RELEASE_HANDOVER_PRIVATE_KEY: key, ...extra });

test("Rundlauf: packen, verschlüsseln, Digest melden, öffnen, auspacken ergibt dasselbe Bundle", () => {
  const f = fixture();
  try {
    const digest = sealed(f);
    assert.deepEqual(readdirSync(f.out), ["unsigned.zip.envelope.json"]);
    const envelope = join(f.out, "unsigned.zip.envelope.json");
    assert.equal(digest, sha256(envelope));
    assert.ok(!readFileSync(envelope).includes(MARKER), "kein Klartext im Umschlag");
    assert.deepEqual(readdirSync(f.env.RUNNER_TEMP), [], "Klartext-Archiv ist weg");
    const opened = open(f, digest);
    assert.equal(opened.status, 0, opened.out);
    assert.match(opened.out, /^PASS handover-opened\n$/);
    assert.deepEqual(readdirSync(f.work), ["unsigned.zip"]);
    assert.deepEqual(readdirSync(f.env.RUNNER_TEMP), [], "Schlüsseldatei ist weg");
    const extracted = f.py("extract-app-bundle.py", [join(f.work, "unsigned.zip"), join(f.root, "aus"), "Probe.app"]);
    assert.equal(extracted.status, 0, extracted.out);
    assert.deepEqual(picture(join(f.root, "aus/Probe.app")), picture(f.app));
    assert.equal(Object.values(picture(f.app)).filter((v) => v.startsWith("link ")).length, 3);
  } finally { f.close(); }
});

test("versiegeln: ohne gültigen öffentlichen Schlüssel oder in einen vorhandenen Ordner entsteht nichts", () => {
  for (const key of [null, "", "kein schluessel\n", `${pair(2048).publicBase64}\n`]) {
    const f = fixture({ key });
    try {
      const r = f.sh("seal-build-handover.sh", [f.app, f.out]);
      assert.notEqual(r.status, 0);
      assert.ok(!existsSync(join(f.out, "unsigned.zip.envelope.json")));
      assert.equal(readFileSync(f.env.GITHUB_OUTPUT, "utf8"), "");
      assert.deepEqual(readdirSync(f.env.RUNNER_TEMP), []);
      assert.ok(!r.out.includes(MARKER));
    } finally { f.close(); }
  }
  const f = fixture();
  try {
    rmSync(join(f.root, "gate/config/release-handover-public-key.b64"));
    writeFileSync(join(f.root, "fremd.b64"), `${OTHER.publicBase64}\n`);
    symlinkSync(join(f.root, "fremd.b64"), join(f.root, "gate/config/release-handover-public-key.b64"));
    assert.equal(f.sh("seal-build-handover.sh", [f.app, f.out]).status, 1, "Schlüssel als Verweis");
    mkdirSync(f.out);
    assert.notEqual(f.sh("seal-build-handover.sh", [f.app, f.out]).status, 0, "Ausgabe-Ordner muss neu sein");
    assert.equal(f.sh("seal-build-handover.sh", [f.app]).status, 64);
    assert.equal(f.sh("seal-build-handover.sh", [f.app, f.out, "x"]).status, 64);
  } finally { f.close(); }
});

function closed(name, arrange, pattern) {
  test(`öffnen abgewiesen: ${name}`, () => {
    const f = fixture();
    try {
      const digest = sealed(f);
      const r = arrange(f, digest);
      assert.notEqual(r.status, 0, r.out);
      if (pattern) assert.match(r.out, pattern);
      assert.ok(!existsSync(join(f.work, "unsigned.zip")), "kein Klartext");
      assert.deepEqual(readdirSync(f.env.RUNNER_TEMP), [], "keine Schlüsseldatei bleibt liegen");
      assert.ok(!r.out.includes("PRIVATE KEY") && !r.out.includes(MARKER));
    } finally { f.close(); }
  });
}
const envelopeOf = (f) => join(f.out, "unsigned.zip.envelope.json");
closed("Digest passt nicht", (f, digest) => open(f, digest.replace(/^./, (c) => (c === "0" ? "1" : "0"))), /passt nicht zum Digest/);
closed("Digest fehlt", (f) => open(f, ""), /Digest des Umschlags fehlt/);
closed("Digest in Großbuchstaben", (f, digest) => open(f, digest.toUpperCase()), /Digest des Umschlags fehlt/);
closed("Digest mit zweiter Zeile", (f, digest) => open(f, `${digest}\n${digest}`), /Digest des Umschlags fehlt/);
closed("Umschlag nach dem Melden verändert", (f, digest) => { writeFileSync(envelopeOf(f), readFileSync(envelopeOf(f), "utf8").replace(/"/, ' "')); return open(f, digest); }, /passt nicht zum Digest/);
closed("zweite Datei in der Übergabe", (f, digest) => { writeFileSync(join(f.out, "zusatz"), "x"); return open(f, digest); }, /nicht genau den Umschlag/);
closed("Unterordner in der Übergabe", (f, digest) => { mkdirSync(join(f.out, "ordner")); return open(f, digest); }, /nicht genau den Umschlag/);
closed("Umschlag ist ein Verweis", (f, digest) => {
  const real = join(f.root, "echt.json");
  copyFileSync(envelopeOf(f), real);
  rmSync(envelopeOf(f));
  symlinkSync(real, envelopeOf(f));
  return open(f, digest);
}, /nicht genau den Umschlag/);
closed("Übergabe-Ordner ist ein Verweis", (f, digest) => { symlinkSync(f.out, join(f.root, "verweis")); return f.sh("open-build-handover.sh", [join(f.root, "verweis"), f.work], { HANDOVER_SHA256: digest, RELEASE_HANDOVER_PRIVATE_KEY: KEYS.privatePem }); }, /Uebergabe fehlt/);
closed("Übergabe fehlt", (f, digest) => { rmSync(f.out, { recursive: true }); return open(f, digest); }, /Uebergabe fehlt/);
closed("Schlüssel fehlt", (f, digest) => open(f, digest, ""), /Uebergabe-Schluessel fehlt/);
closed("fremder Schlüssel", (f, digest) => open(f, digest, OTHER.privatePem));
closed("Umschlag an einen fremden Schlüssel, Digest stimmt", (f) => {
  // Jeder kann an den öffentlichen Schlüssel verschlüsseln: der Digest des Bau-Jobs entscheidet, nicht der Schlüssel.
  writeFileSync(join(f.root, "gate/config/release-handover-public-key.b64"), `${OTHER.publicBase64}\n`);
  rmSync(f.out, { recursive: true });
  writeFileSync(f.env.GITHUB_OUTPUT, "");
  return open(f, sealed(f));
});
closed("Arbeitsordner gibt es schon", (f, digest) => { mkdirSync(f.work); return open(f, digest); });
closed("falsche Zahl von Argumenten", (f, digest) => f.sh("open-build-handover.sh", [f.out], { HANDOVER_SHA256: digest, RELEASE_HANDOVER_PRIVATE_KEY: KEYS.privatePem }), /usage/);

test("öffnen: erst der Digest, dann der Schlüssel", () => {
  const f = fixture();
  try {
    sealed(f);
    // Mit falschem Digest wird der Schlüssel nie angefasst: auch ein unbrauchbarer löst nur die Digest-Meldung aus.
    const r = open(f, "0".repeat(64), "unbrauchbar");
    assert.equal(r.status, 1);
    assert.match(r.out, /passt nicht zum Digest/);
    assert.ok(!existsSync(f.work));
  } finally { f.close(); }
});

test("packen: Rechte nur als ausführbar oder nicht, Archiv neu und nur für den eigenen Benutzer", () => {
  const f = fixture();
  try {
    const archive = join(f.root, "a.zip");
    const r = f.py("pack-app-bundle.py", [f.app, archive]);
    assert.equal(r.status, 0, r.out);
    assert.match(r.out, /^packed: \d+ entries\n$/);
    assert.equal(statSync(archive).mode & 0o777, 0o600);
    assert.equal(f.py("pack-app-bundle.py", [f.app, archive]).status, 1, "vorhandenes Archiv bleibt unberührt");
    assert.equal(f.py("pack-app-bundle.py", [f.app]).status, 64);
    assert.equal(f.py("pack-app-bundle.py", [join(f.root, "fehlt.app"), join(f.root, "b.zip")]).status, 1);
    symlinkSync(f.app, join(f.root, "Verweis.app"));
    assert.equal(f.py("pack-app-bundle.py", [join(f.root, "Verweis.app"), join(f.root, "c.zip")]).status, 1, "Bundle als Verweis");
  } finally { f.close(); }
});

for (const [name, make] of [
  ["Verweis mit absolutem Ziel", (app) => symlinkSync("/etc/hosts", join(app, "Contents/Resources/aussen"))],
  ["Verweis nach oben", (app) => symlinkSync("../../../aussen", join(app, "Contents/Resources/aussen"))],
  ["Verweis mit Punkt im Ziel", (app) => symlinkSync("./leer", join(app, "Contents/Resources/punkt"))],
  ["Ordner-Verweis nach oben", (app) => symlinkSync("../..", join(app, "Contents/Resources/hoch"))],
  ["weder Datei noch Ordner noch Verweis", (app) => assert.equal(spawnSync("mkfifo", [join(app, "Contents/Resources/rohr")]).status, 0)],
]) {
  test(`packen abgewiesen: ${name}`, () => {
    const f = fixture();
    try {
      make(f.app);
      const r = f.py("pack-app-bundle.py", [f.app, join(f.root, "a.zip")]);
      assert.equal(r.status, 1, r.out);
      assert.match(r.out, /^rejected: (link target|entry type)\n$/);
      assert.notEqual(f.sh("seal-build-handover.sh", [f.app, f.out]).status, 0, "auch das Versiegeln bricht ab");
      assert.ok(!existsSync(join(f.out, "unsigned.zip.envelope.json")));
    } finally { f.close(); }
  });
}
